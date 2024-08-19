import * as aws from '@pulumi/aws'
import * as pulumi from '@pulumi/pulumi'
import * as docker from '@pulumi/docker'

export const createRuntimeRole = (): aws.iam.Role => {
	const assumeRolePolicyStatements: aws.iam.PolicyStatement[] = [
		{
			Effect: 'Allow',
			Action: 'sts:AssumeRole',
			Principal: {
				Service: 'lambda.amazonaws.com', // Allows using the role as a lambda execution role
			},
		},
	]
	const policyStatements: aws.iam.PolicyStatement[] = [
		{
			Effect: 'Allow',
			Action: [
				'logs:CreateLogGroup',
				'logs:CreateLogStream',
			],
			Resource: '*',
		},
		{
			Effect: 'Allow',
			Action: ['logs:PutLogEvents'],
			Resource: '*',
		},
		{
			Effect: 'Allow',
			Action: ['lambda:InvokeFunction'],
			Resource: '*',
		},

		// As per https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html#configuration-vpc-permissions
		{
			Effect: 'Allow',
			Action: [
				'ec2:DescribeNetworkInterfaces',
				'ec2:DescribeSubnets',
				'ec2:CreateNetworkInterface',
				'ec2:DeleteNetworkInterface',
				'ec2:AssignPrivateIpAddresses',
				'ec2:UnassignPrivateIpAddresses',
			],
			Resource: '*',
		},
	]

	// Runtime role
	const runtimeRole = new aws.iam.Role('pulumi-bug-report', {
		assumeRolePolicy: { // Define who/what services can assume this role
			Version: '2012-10-17',
			Statement: assumeRolePolicyStatements,
		},
	})

	// Runtime role policy
	const runtimeRolePolicy = new aws.iam.Policy('pulumi-bug-report-runtime-policy', {
		description: pulumi.interpolate`Policy for IAM role ${runtimeRole.name}`,
		policy: {
			Version: '2012-10-17',
			Statement: policyStatements,
		},
	})

	// Attach policies to roles
	new aws.iam.RolePolicyAttachment('pulumi-bug-report-runtime-role-policy-attachment', {
		role: runtimeRole,
		policyArn: runtimeRolePolicy.arn,
	})

	return runtimeRole
}

export const createImageRepository = () => {
	const ecrRepository = new aws.ecr.Repository('pulumi-bug-report', { forceDelete: true })

	const registryCredentials: docker.types.input.Registry = {
		server: ecrRepository.repositoryUrl,
	}

	// Do not fetch ECR credentials in pulumi previews
	if (!pulumi.runtime.isDryRun()) {
		const authToken = aws.ecr.getAuthorizationTokenOutput({ registryId: ecrRepository.registryId })

		registryCredentials.username = pulumi.output(authToken.apply(authToken => authToken.userName))
		registryCredentials.password = pulumi.secret(authToken.apply(authToken => authToken.password))
	}

	return { ecrRepository, registryCredentials }
}

export const createImage = (
	ecrRepository: aws.ecr.Repository,
	registryCredentials: docker.types.input.Registry,
): docker.Image => {
	/*
	 * Build an image from the "src" directory (containing the Dockerfile),
	 * and publish it to our ECR repository provisioned above.
	 *
	 * We have to perform this step in Pulumi because of a limitation with AWS Lambda:
	 * The image must exist before the lambda function is created.
	 */
	const image = new docker.Image('pulumi-bug-report', {
		imageName: pulumi.interpolate`${ecrRepository.repositoryUrl}:${process.env.CI_COMMIT_SHA}`,
		build: {
			context: '../src', // path relative to where the pulumi command is run
			platform: 'linux/amd64',
		},
		registry: registryCredentials,
	})

	return image
}

export interface ZoneConfig {
	zone: string
	publicSubnet?: aws.ec2.Subnet
	privateSubnet?: aws.ec2.Subnet
}
export const createVpc = () => {
	// Create a VPC
	const vpc = new aws.ec2.Vpc('pulumi-bug-report-vpc', {
		cidrBlock: '10.0.0.0/16',
		enableDnsHostnames: true,
		enableDnsSupport: true,
		tags: { Name: 'pulumi-bug-report' },
	})

	// 2 availability zones (us-east-1a and us-east-1b) is recommended for high availability.
	// each zone will have one public and one private subnet
	const zones: ZoneConfig[] = [
		{
			zone: 'us-east-1a',
			publicSubnet: undefined,
			privateSubnet: undefined,
		},
		{
			zone: 'us-east-1b',
			publicSubnet: undefined,
			privateSubnet: undefined,
		},
	]

	// Create an internet gateway for public subnets the VPC.
	// This allows instances with public IPs (ones in the public subnet) to access the internet.
	const internetGateway = new aws.ec2.InternetGateway('pulumi-bug-report-internet-gateway', {
		vpcId: vpc.id,
		tags: { Name: 'pulumi-bug-report' },
	})

	// Create public subnets. In our case, we only use public subnets to host the NAT Gateways
	// that are used by the resources in private subnets to make http requests to the broader internet
	const publicSubnets = createPublicSubnets(vpc, internetGateway, zones)

	// Create private subnets. These are used to host our resources (eg. lambdas, RDS instances)
	const privateSubnets = createPrivateSubnets(vpc, internetGateway, zones)

	setVpcSecurityRules(vpc, [...publicSubnets, ...privateSubnets])

	return {
		vpc,
		privateSubnets,
	}
}

// Create public subnets and their associated networking configuration
// A public subnet is a subnet that has a default route in its route table that points to an internet gateway
const createPublicSubnets = (
	vpc: aws.ec2.Vpc,
	internetGateway: aws.ec2.InternetGateway,
	zoneConfigs: ZoneConfig[],
) => {
	// Create a route table to route internet-bound traffic to the internet gateway
	const publicRouteTable = new aws.ec2.RouteTable('pulumi-bug-report-public-route-table', {
		vpcId: vpc.id,
		routes: [
			{
				cidrBlock: '0.0.0.0/0',
				gatewayId: internetGateway.id,
			},
		],
		tags: { Name: 'pulumi-bug-report-public' },
	})

	// Create a public subnet in each zone
	const publicSubnets: aws.ec2.Subnet[] = []
	for (const zoneConfig of zoneConfigs) {
		const { zone } = zoneConfig
		const subnetCount = countSubnets(zoneConfigs)

		const publicSubnet = new aws.ec2.Subnet(`pulumi-bug-report-${zone}-public-subnet`, {
			vpcId: vpc.id,
			cidrBlock: `10.0.${subnetCount + 1}.0/24`,
			availabilityZone: zone,
			mapPublicIpOnLaunch: false,
			tags: { Name: `pulumi-bug-report-${zone}-public` },
		})

		// Associate the route tables with their subnets
		// Once the default route in a subnet's route table points to an internet gateway,
		// by definition, it is a public subnet
		new aws.ec2.RouteTableAssociation(`pulumi-bug-report-${zone}-public-route-table-association`, {
			subnetId: publicSubnet.id,
			routeTableId: publicRouteTable.id,
		})

		publicSubnets.push(publicSubnet)
		zoneConfig.publicSubnet = publicSubnet
	}

	return publicSubnets
}

// Create private subnets and their associated networking configuration
// A private subnet is a subnet that has a default route in its route table that does not point to an internet gateway
const createPrivateSubnets = (
	vpc: aws.ec2.Vpc,
	internetGateway: aws.ec2.InternetGateway,
	zoneConfigs: ZoneConfig[],
) => {
	// Create a private subnet in each zone
	const privateSubnets: aws.ec2.Subnet[] = []
	for (const zoneConfig of zoneConfigs) {
		const { zone, publicSubnet } = zoneConfig
		const subnetCount = countSubnets(zoneConfigs)

		const privateSubnet = new aws.ec2.Subnet(`pulumi-bug-report-${zone}-private-subnet`, {
			vpcId: vpc.id,
			cidrBlock: `10.0.${subnetCount + 1}.0/24`,
			availabilityZone: zone,
			mapPublicIpOnLaunch: false,
			tags: { Name: `pulumi-bug-report-${zone}-private` },
		})

		// Create NAT gateways so that instances in private subnets can connect to services outside the VPC,
		// but external services cannot initiate a connection with instances in the private subnets.
		// NAT gateways have to be deployed in a public subnet and have a public IP address.
		// Since we set mapPublicIpOnLaunch to false, in the public subnet, we create an IP here.
		const natGatewayEip = new aws.ec2.Eip(`pulumi-bug-report-${zone}-eip`, {
			domain: 'vpc',
			tags: { Name: `pulumi-bug-report-${zone}` },
		})
		const natGateway = new aws.ec2.NatGateway(`pulumi-bug-report-${zone}-nat-gateway`, {
			allocationId: natGatewayEip.id,
			connectivityType: 'public',
			subnetId: publicSubnet!.id,
			tags: { Name: `pulumi-bug-report-${zone}` },
		}, { dependsOn: [internetGateway] })

		// Create route tables to route internet-bound traffic to the nat gateways
		const privateRouteTable = new aws.ec2.RouteTable(`pulumi-bug-report-${zone}-private-route-table`, {
			vpcId: vpc.id,
			routes: [
				{
					cidrBlock: '0.0.0.0/0',
					natGatewayId: natGateway.id,
				},
			],
			tags: { Name: `pulumi-bug-report-${zone}-private` },
		})

		// Associate the route tables with their subnets
		// Since the default route in a subnet's route table points to a NAT gateway,
		// (as opposed to an internet gateway), it is not a public subnet
		new aws.ec2.RouteTableAssociation(`pulumi-bug-report-${zone}-private-route-table-association`, {
			subnetId: privateSubnet.id,
			routeTableId: privateRouteTable.id,
		})

		privateSubnets.push(privateSubnet)
		zoneConfig.privateSubnet = privateSubnet
	}

	return privateSubnets
}

const setVpcSecurityRules = (vpc: aws.ec2.Vpc, subnets: aws.ec2.Subnet[]) => {
	// Set the default network ACL egress and ingress rules.
	// Note that more restrictive rules are set at the security group level
	const vpcTrafficRules: aws.types.input.ec2.NetworkAclIngress[] = [
		{
			// Allow HTTPS traffic to all IPs
			// This is neded because some of the APIs we interact with (notably: Slack) don't share IP lists.
			ruleNo: 100,
			action: 'allow',
			protocol: 'tcp',
			cidrBlock: '0.0.0.0/0',
			fromPort: 443,
			toPort: 443,
		},
		{
			// Allow traffic on ephemeral ports used by NAT gateways and Lambda
			// Source: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#nacl-ephemeral-ports
			ruleNo: 300,
			action: 'allow',
			protocol: 'tcp',
			cidrBlock: '0.0.0.0/0',
			fromPort: 1024,
			toPort: 65535,
		},
	]
	new aws.ec2.DefaultNetworkAcl('pulumi-bug-report-default-network-acl', {
		defaultNetworkAclId: vpc.defaultNetworkAclId,
		ingress: vpcTrafficRules,
		egress: vpcTrafficRules,
		subnetIds: subnets.map(subnet => subnet.id),
		tags: { Name: 'pulumi-bug-report' },
	})
	// Ensure default security group denies all ingress and egress traffic by omitting ingress and egress parameters
	new aws.ec2.DefaultSecurityGroup('pulumi-bug-report-default-security-group', {
		vpcId: vpc.id,
		tags: { Name: 'pulumi-bug-report-default-security-group' },
	})
}

const countSubnets = (zones: ZoneConfig[]) => (
	zones.reduce((currentCount, zone) => {
		if (zone.publicSubnet) currentCount += 1
		if (zone.privateSubnet) currentCount += 1

		return currentCount
	}, 0)
)

/* Create a Security Group in a VPC
 * We use this helper function to avoid some common pitfalls when using security groups with Pulumi/Terraform.
 * Relevant docs:
 * - Notes/warnings in the Pulumi docs: https://www.pulumi.com/registry/packages/aws/api-docs/ec2/securitygroup
 * - This issue & comment: https://github.com/hashicorp/terraform-provider-aws/issues/265#issuecomment-1462631019
 */
interface CreateSecurityGroupOptions {
	vpcId: pulumi.Input<string>
	egressRules?: Omit<aws.vpc.SecurityGroupEgressRuleArgs, 'securityGroupId'>[]
	ingressRules?: Omit<aws.vpc.SecurityGroupIngressRuleArgs, 'securityGroupId'>[]
}
export const createSecurityGroup = (
	{ vpcId, ingressRules = [], egressRules = [] }: CreateSecurityGroupOptions,
) => {
	// Note: do not use the ingress and egress inline arguments to the security group resources,
	// as per the notes in the docs: https://www.pulumi.com/registry/packages/aws/api-docs/ec2/securitygroup
	const securityGroup = new aws.ec2.SecurityGroup('pulumi-bug-report-security-group', {
		vpcId,
		description: `Security group for pulumi-bug-report`,
		tags: { Name: 'pulumi-bug-report' },
	}, { customTimeouts: { delete: '2m' } })

	for (const [index, ingressRule] of ingressRules.entries()) {
		new aws.vpc.SecurityGroupIngressRule(`pulumi-bug-report-sg-ingress-rule-${index}`, {
			securityGroupId: securityGroup.id,
			...ingressRule,
			tags: { Name: `pulumi-bug-report-sg-ingress-rule-${index}`, ...ingressRule.tags },
		})
	}

	for (const [index, egressRule] of egressRules.entries()) {
		new aws.vpc.SecurityGroupEgressRule(`pulumi-bug-report-sg-egress-rule-${index}`, {
			securityGroupId: securityGroup.id,
			...egressRule,
			tags: { Name: `pulumi-bug-report-sg-egress-rule-${index}`, ...egressRule.tags },
		})
	}

	return securityGroup
}
