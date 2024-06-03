# authy

A serverless authentication and authorisation stack.

## Description

`authy` is a serverless application that can be deployed via the AWS Serverless Application Repository to provide authentication and authorisation for your application. It provides authentication services via Open ID Connect (OIDC) with AWS Cognito as an identity provider, and it provides a centralised policy decision point that uses an authorisation policy that you provide to make authorisation decisions for your app.

A key feature of `authy` is that it externalises authentication and authorisation. In other words, your application code doesn't need to worry about these concerns, and your app can also be deployed standalone so that your tests can focus on business logic rather than cross-cutting concerns like authentication and authorisation.

Another key feature is a centralised policy decision point. Rather that authorisation logic scattered about your codebase, making it hard to reason about and test authorisation, authorisation logic is centralised in a single place (`pdp.py`).

## Getting started

`authy` is available via the AWS Serverless Application Repository. Include it in your SAM / CloudFormation template as a serverless application`.

```yaml
Authy:
  Type: AWS::Serverless::Application
  Properties:
    Location:
      ApplicationId: 'arn:aws:serverlessrepo:eu-west-2:211125310871:applications/authy'
      SemanticVersion: <CURRENT_VERSION>
    Parameters:
      ...
```

To implement your policy decision point, you need to provide a `pdp` module with a `check_authz(event, id_attrs)` function. `event` is the standard API Gateway V2 (HTTP API) event, and `id_attrs` is a dict containing `user`, `groups` and `name` attributes extracted from the claims in the JWT. Your authorisation code can make use of these parameters to allow or deny access. Here's an example `pdp.py`:

```python
import logging

logger = logging.getLogger(__name__)


def check_authz(event, id_attrs):
    group = id_attrs.get('groups', [])

    if 'Admins' in group:
        return True, {}

    http = event['requestContext']['http']
    path = http['path']

    if 'BlogAdmins' in group:
        if path.startswith('/blog/'):
            return True, {}

    logger.info('No rules matched, access denied')
    return False, {}
```

To make your `pdp.py` available to `authy`, package it up as a Lambda Layer and then pass the ARN as a parameter:

```yaml
PDPLayer:
  Type: AWS::Serverless::LayerVersion
  Properties:
    LayerName: PDPLayer
    Description: PDPLayer
    ContentUri: pdp/
    CompatibleRuntimes:
      - python3.12
    CompatibleArchitectures:
      - arm64
    RetentionPolicy: Delete
  Metadata:
    BuildMethod: python3.12
    BuildArchitecture: arm64

Authy:
    ...
    Parameters:
      PDPLayerArn: !Ref PDPLayer
      ...
```

You can expose the authentication URLs (`/auth/login`, `/auth/logout`, and `/auth/oidc`) via CloudFront. `authy` can also accept an `OriginKey` parameter which can be used to ensure that requests can only come via CloudFront:

```yaml
OriginKey:
  Type: AWS::SecretsManager::Secret
  Properties:
    Name: OriginKey
    GenerateSecretString:
      ExcludePunctuation: true
      PasswordLength: 64

Authy:
    ...
    Parameters:
      OriginKey: !Sub '{{resolve:secretsmanager:${OriginKey}}}'
      ...

CloudFrontDistro:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      Origins:
        - DomainName: !GetAtt Authy.Outputs.AuthEndpointsDomain
          Id: AuthEndpoint
          OriginCustomHeaders:
            - HeaderName: X-Custom-Origin-Key
              HeaderValue: !Sub '{{resolve:secretsmanager:${OriginKey}}}'
    ...
```

The other parameters should be fairly straightforward and self-explanatory.

The outputs from this serverless application can then be used to secure other APIs:

```yaml
AuthenticatedEndpoint:
  Type: AWS::Serverless::HttpApi
  Properties:
    Auth:
      Authorizers:
        CognitoAbacAuthorizer:
          FunctionArn: !GetAtt Authy.Outputs.CognitoAbacAuthorizerArn
          AuthorizerPayloadFormatVersion: 2.0
          EnableSimpleResponses: true
          FunctionInvokeRole: !GetAtt Authy.Outputs.LambdaAuthorizerRoleArn
      DefaultAuthorizer: CognitoAbacAuthorizer
```

An authentication failure will return a 401. If you're using `authy` to front a web app, you probably want an authentication failure to return a redirect to `/auth/login`, and to attempt a silent re-auth if a refresh token exists. You can implement this in `authy` using [authn-redirector](https://github.com/andycaine/authn-redirector).
