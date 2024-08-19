# Use node image for dependencies because the lambda image does not have yarn installed
FROM node:20-alpine AS dependencies

WORKDIR /app

# Install dependencies
RUN corepack enable
COPY package*.json yarn*.lock .yarnrc.yml ./
RUN yarn install --immutable

# Compile app
COPY . .
RUN yarn run build

# Remove dev dependencies
RUN yarn workspaces focus --production

# Use the lambda image because it comes with the lambda nodejs runtime interface client installed and configured
# To avoid doing a multi-stage build, we could use the aws-lambda-ric npm package and follow instructions on this guide:
# https://docs.aws.amazon.com/lambda/latest/dg/images-create.html#images-create-from-alt
# However, we are stuck with the multi-stage build solution for now
# because aws-lambda-ric has yet to be updated to support node 16.
FROM public.ecr.aws/lambda/nodejs:20 AS production

# Copy source code
COPY --from=dependencies /app .

# Set default command that is called when the container runs
CMD ["dist/index.handler"]
