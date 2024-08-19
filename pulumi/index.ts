import * as aws from '@pulumi/aws'
import * as pulumi from '@pulumi/pulumi'
import {
	createImage,
	createImageRepository,
	createRuntimeRole,
	createSecurityGroup,
	createVpc,
} from './helpers.js'

const lambdaExecRole = createRuntimeRole()

const { ecrRepository, registryCredentials } = createImageRepository()

const image = createImage(ecrRepository, registryCredentials)

const { vpc, privateSubnets } = createVpc()

/* Create a Security Group in a VPC
 * Relevant docs:
 * - Notes/warnings in the Pulumi docs: https://www.pulumi.com/registry/packages/aws/api-docs/ec2/securitygroup
 * - This issue & comment: https://github.com/hashicorp/terraform-provider-aws/issues/265#issuecomment-1462631019
 */

// Note: do not use the ingress and egress inline arguments to the security group resources,
// as per the notes in the docs: https://www.pulumi.com/registry/packages/aws/api-docs/ec2/securitygroup
const securityGroup = new aws.ec2.SecurityGroup('pulumi-bug-report-security-group', {
	vpcId: vpc.id,
	description: `Security group for pulumi-bug-report`,
	tags: { Name: 'pulumi-bug-report' },
}, { customTimeouts: { delete: '2m' } })

new aws.vpc.SecurityGroupIngressRule('pulumi-bug-report-sg-ingress-rule-https-oubound', {
	securityGroupId: securityGroup.id,
	description: 'Allow all TCP HTTPS outbound traffic',
	ipProtocol: 'tcp',
	fromPort: 443, // Allow only HTTPS traffic
	toPort: 443,

	// Allow traffic to all IPs
	cidrIpv4: '0.0.0.0/0',
	tags: { Name: 'pulumi-bug-report-sg-ingress-rule-https-outbound' },
})

for (const [index, privateSubnet] of privateSubnets.entries()) {
	const cidrIpv4 = privateSubnet.cidrBlock.apply((cidrBlock) => cidrBlock!)

	new aws.vpc.SecurityGroupIngressRule(`pulumi-bug-report-sg-ingress-rule-subnet-${index}`, {
		securityGroupId: securityGroup.id,
		description: 'Allow outgoing traffic to private subnet on database port',
		ipProtocol: 'tcp',
		fromPort: 5432,
		toPort: 5432,
		cidrIpv4,
		tags: { Name: `pulumi-bug-report-sg-ingress-rule-${index}` },
	})
}

const lambdaFunction = new aws.lambda.Function('pulumi-bug-report', {
		packageType: 'Image',
		imageUri: image.imageName,
		role: lambdaExecRole.arn,
		imageConfig: { commands: ['dist/index.handler'] },
		vpcConfig: {
			subnetIds: privateSubnets.map(subnet => subnet.id),
			securityGroupIds: [securityGroup.id],
		},
	},
	// Attempt to fix the issue where security groups take forever to update when they are attached to a lambda function
	// As per: https://github.com/hashicorp/terraform-provider-aws/issues/265#issuecomment-1462631019
	// Note: this doesn't seem to have the intended effect/fix the issue either
	{ replaceOnChanges: ['vpcConfig.securityGroupIds'] },
)
