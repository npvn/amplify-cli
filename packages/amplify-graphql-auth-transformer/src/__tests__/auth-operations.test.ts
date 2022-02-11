import { ModelTransformer } from '@aws-amplify/graphql-model-transformer';
import { GraphQLTransform } from '@aws-amplify/graphql-transformer-core';
import { AppSyncAuthConfiguration } from '@aws-amplify/graphql-transformer-interfaces';
import { ResourceConstants } from 'graphql-transformer-common';
import { AccessControlMatrix } from '../accesscontrol';
import { AuthTransformer } from '../graphql-auth-transformer';
import { MODEL_OPERATIONS } from '../utils';

test('invalid read list operation combination', () => {
  const authConfig: AppSyncAuthConfiguration = {
    defaultAuthentication: {
      authenticationType: 'AMAZON_COGNITO_USER_POOLS',
    },
    additionalAuthenticationProviders: [],
  };
  const invalidSchema = `
    type Test @model @auth(rules: [{ allow: public, operations: [ read, list, create ]}]) {
      id: ID!
      name: String
    }`;
  const transformer = new GraphQLTransform({
    authConfig,
    transformers: [new ModelTransformer(), new AuthTransformer()],
  });
  expect(() => transformer.transform(invalidSchema)).toThrowError(
    `'list' operation is specified in addition to 'read'. Either remove 'read' to limit access only to 'list' or only keep 'read' to grant both 'get' and 'list' access.`,
  );
});

test('invalid read get operation combination', () => {
  const authConfig: AppSyncAuthConfiguration = {
    defaultAuthentication: {
      authenticationType: 'AMAZON_COGNITO_USER_POOLS',
    },
    additionalAuthenticationProviders: [],
  };
  const invalidSchema = `
    type Test @model @auth(rules: [{ allow: public, operations: [ read, get, create ]}]) {
      id: ID!
      name: String
    }`;
  const transformer = new GraphQLTransform({
    authConfig,
    transformers: [new ModelTransformer(), new AuthTransformer()],
  });
  expect(() => transformer.transform(invalidSchema)).toThrowError(
    `'get' operation is specified in addition to 'read'. Either remove 'read' to limit access only to 'get' or only keep 'read' to grant both 'get' and 'list' access.`,
  );
});

test('read access control', () => {
  /*
  given the following schema
  type TestList @model @auth(rules: [{ allow: public, operations: [ read, create ]}]) {
    id: ID!
    name: String
  }
  */

  const ownerRole = 'userPools:owner:id';
  const typeFields = ['id', 'name'];

  const acm = new AccessControlMatrix({
    name: 'TestList',
    resources: typeFields,
    operations: MODEL_OPERATIONS,
  });

  acm.setRole({
    role: ownerRole,
    operations: ['get', 'list'],
  });

  typeFields.forEach(field => {
    expect(acm.isAllowed(ownerRole, field, 'list')).toBe(true);
    expect(acm.isAllowed(ownerRole, field, 'get')).toBe(true);
  });
});

test('list access control', () => {
  /*
  given the following schema
  type TestList @model @auth(rules: [{ allow: public, operations: [ list, create ]}]) {
    id: ID!
    name: String
  }
  */

  const ownerRole = 'userPools:owner:id';
  const typeFields = ['id', 'name'];

  const acm = new AccessControlMatrix({
    name: 'TestList',
    resources: typeFields,
    operations: MODEL_OPERATIONS,
  });

  acm.setRole({
    role: ownerRole,
    operations: ['list'],
  });

  typeFields.forEach(field => {
    expect(acm.isAllowed(ownerRole, field, 'list')).toBe(true);
    expect(acm.isAllowed(ownerRole, field, 'get')).toBe(false);
  });
});

test('get access control', () => {
  /*
  given the following schema
  type TestList @model @auth(rules: [{ allow: public, operations: [ get, create ]}]) {
    id: ID!
    name: String
  }
  */

  const ownerRole = 'userPools:owner:id';
  const typeFields = ['id', 'name'];

  const acm = new AccessControlMatrix({
    name: 'TestList',
    resources: typeFields,
    operations: MODEL_OPERATIONS,
  });

  acm.setRole({
    role: ownerRole,
    operations: ['get'],
  });

  typeFields.forEach(field => {
    expect(acm.isAllowed(ownerRole, field, 'list')).toBe(false);
    expect(acm.isAllowed(ownerRole, field, 'get')).toBe(true);
  });
});

test('read get list auth operations', () => {
  const authConfig: AppSyncAuthConfiguration = {
    defaultAuthentication: {
      authenticationType: 'API_KEY',
    },
    additionalAuthenticationProviders: [],
  };
  const validSchema = `
    type TestList @model @auth(rules: [{ allow: public, operations: [ list ]}]) {
      id: ID!
      name: String
    }

    type TestGet @model @auth(rules: [{ allow: public, operations: [ get ]}]) {
      id: ID!
      name: String
    }

    type TestRead @model @auth(rules: [{ allow: public, operations: [ read ]}]) {
      id: ID!
      name: String
    }
  `;

  const transformer = new GraphQLTransform({
    authConfig,
    transformers: [new ModelTransformer(), new AuthTransformer()],
  });

  const out = transformer.transform(validSchema);
  expect(out).toBeDefined();

  expect(out.resolvers['Query.getTestList.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Query.listTestLists.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Subscription.onCreateTestList.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Subscription.onDeleteTestList.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Subscription.onUpdateTestList.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Query.getTestList.auth.1.req.vtl']).not.toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Query.listTestLists.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Subscription.onCreateTestList.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Subscription.onDeleteTestList.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Subscription.onUpdateTestList.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');

  expect(out.resolvers['Query.getTestGet.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Query.listTestGets.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Subscription.onCreateTestGet.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Subscription.onDeleteTestGet.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Subscription.onUpdateTestGet.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Query.getTestGet.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Query.listTestGets.auth.1.req.vtl']).not.toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Subscription.onCreateTestGet.auth.1.req.vtl']).not.toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Subscription.onDeleteTestGet.auth.1.req.vtl']).not.toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Subscription.onUpdateTestGet.auth.1.req.vtl']).not.toContain('#set( $isAuthorized = true )');

  expect(out.resolvers['Query.getTestRead.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Query.listTestReads.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Subscription.onCreateTestRead.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Subscription.onDeleteTestRead.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Subscription.onUpdateTestRead.auth.1.req.vtl']).toMatchSnapshot();
  expect(out.resolvers['Query.getTestRead.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Query.listTestReads.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Subscription.onCreateTestRead.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Subscription.onDeleteTestRead.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');
  expect(out.resolvers['Subscription.onUpdateTestRead.auth.1.req.vtl']).toContain('#set( $isAuthorized = true )');
});
