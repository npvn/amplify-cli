import { $TSAny, $TSContext, $TSObject, JSONUtilities, pathManager, stateManager } from 'amplify-cli-core';
import { FunctionParameters, ProjectLayer } from 'amplify-function-plugin-interface';
import inquirer from 'inquirer';
import _ from 'lodash';
import path from 'path';
import { categoryName } from '../../../constants';
import { getNewCFNEnvVariables, getNewCFNParameters } from '../utils/cloudformationHelpers';
import {
  advancedSettingsList,
  cronJobSetting,
  functionParametersFileName,
  lambdaLayerSetting,
  secretsConfiguration,
  parametersFileName,
  resourceAccessSetting,
  ServiceName,
} from '../utils/constants';
import { merge } from '../utils/funcParamsUtils';
import { runtimeWalkthrough, templateWalkthrough } from '../utils/functionPluginLoader';
import { convertLambdaLayerMetaToLayerCFNArray } from '../utils/layerArnConverter';
import { loadFunctionParameters } from '../utils/loadFunctionParameters';
import {
  fetchPermissionCategories,
  fetchPermissionResourcesForCategory,
  fetchPermissionsForResourceInCategory,
} from '../utils/permissionMapUtils';
import { consolidateDependsOnForLambda } from '../utils/consolidateDependsOn';
import { secretValuesWalkthrough } from './secretValuesWalkthrough';
import { secretNamesToSecretDeltas } from '../secrets/secretDeltaUtilities';
import { getLocalFunctionSecretNames } from '../secrets/functionSecretsStateManager';
import { tryUpdateTopLevelComment } from '../utils/updateTopLevelComment';
import { addLayersToFunctionWalkthrough } from './addLayerToFunctionWalkthrough';
import autogeneratedParameters from './autogeneratedParameters';
import { askExecRolePermissionsQuestions } from './execPermissionsWalkthrough';
import { generalQuestionsWalkthrough, settingsUpdateSelection } from './generalQuestionsWalkthrough';
import { scheduleWalkthrough } from './scheduleWalkthrough';

/**
 * Starting point for CLI walkthrough that generates a lambda function
 * @param context The Amplify Context object
 */
export async function createWalkthrough(
  context: $TSContext,
  templateParameters: Partial<FunctionParameters>,
): Promise<Partial<FunctionParameters>> {
  // merge in parameters that don't require any additional input
  templateParameters = merge(templateParameters, autogeneratedParameters(context));

  // ask generic function questions and merge in results
  templateParameters = merge(templateParameters, await generalQuestionsWalkthrough(context));
  if (templateParameters.functionName) {
    templateParameters.resourceName = templateParameters.functionName;
  }

  // ask runtime selection questions and merge in results
  if (!templateParameters.runtime) {
    let runtimeSelection = await runtimeWalkthrough(context, templateParameters);
    templateParameters = merge(templateParameters, runtimeSelection[0]);
  }

  // ask template selection questions and merge in results
  templateParameters = merge(templateParameters, await templateWalkthrough(context, templateParameters));

  // list out the advanced settings before asking whether to configure them
  context.print.info('');
  context.print.success('Available advanced settings:');
  advancedSettingsList.forEach(setting => context.print.info('- '.concat(setting)));
  context.print.info('');

  // ask whether to configure advanced settings
  if (await context.amplify.confirmPrompt('Do you want to configure advanced settings?', false)) {
    if (await context.amplify.confirmPrompt('Do you want to access other resources in this project from your Lambda function?')) {
      templateParameters = merge(
        templateParameters,
        await askExecRolePermissionsQuestions(context, templateParameters.functionName, undefined, templateParameters.environmentMap),
      );
    }

    // ask scheduling Lambda questions and merge in results
    templateParameters = merge(templateParameters, await scheduleWalkthrough(context, templateParameters));

    // ask lambda layer questions and merge in results
    templateParameters = merge(templateParameters, await addLayersToFunctionWalkthrough(context, templateParameters.runtime));

    templateParameters = merge(
      templateParameters,
      await secretValuesWalkthrough(secretNamesToSecretDeltas(getLocalFunctionSecretNames(templateParameters.functionName))),
    );
  }

  return templateParameters;
}

async function provideInformation(context, lambdaToUpdate, functionRuntime, currentParameters, scheduleParameters) {
  // Provide general information
  context.print.success('General information');
  context.print.info('| Name: '.concat(lambdaToUpdate));
  context.print.info('| Runtime: '.concat(functionRuntime));
  context.print.info('');

  // Provide resource access permission information
  context.print.success('Resource access permission');
  const currentCategoryPermissions = fetchPermissionCategories(currentParameters.permissions);
  if (currentCategoryPermissions.length) {
    currentCategoryPermissions.forEach(category => {
      const currentResources = fetchPermissionResourcesForCategory(currentParameters.permissions, category);
      currentResources.forEach(resource => {
        const currentPermissions = fetchPermissionsForResourceInCategory(currentParameters.permissions, category, resource);
        const formattedCurrentPermissions = ' ('.concat(currentPermissions.join(', ').concat(')'));
        context.print.info('- '.concat(resource).concat(formattedCurrentPermissions));
      });
    });
  } else {
    context.print.info('- Not configured');
  }
  context.print.info('');

  // Provide scheduling information
  context.print.success('Scheduled recurring invocation');
  if (scheduleParameters.cloudwatchRule && scheduleParameters.cloudwatchRule !== 'NONE') {
    context.print.info('| '.concat(scheduleParameters.cloudwatchRule));
    context.print.info('');
  } else {
    context.print.info('| Not configured');
    context.print.info('');
  }

  // Provide lambda layer information
  context.print.success('Lambda layers');
  if (currentParameters.lambdaLayers && currentParameters.lambdaLayers.length) {
    currentParameters.lambdaLayers.forEach(layer => {
      if (layer.arn) {
        context.print.info('- '.concat(layer.arn));
      } else {
        context.print.info(`- ${layer.resourceName}`);
      }
    });
    context.print.info('');
  } else {
    context.print.info('- Not configured');
    context.print.info('');
  }

  // secrets configuration
  context.print.success('Secrets configuration');
  const currentSecrets = getLocalFunctionSecretNames(lambdaToUpdate);
  if (currentSecrets.length) {
    currentSecrets.forEach(secretName => context.print.info(`- ${secretName}`));
  } else {
    context.print.info('- Not configured');
  }
  context.print.info('');
}

/**
 * TODO this function needs to be refactored so it doesn't have side-effects of writing to CFN files
 */
export async function updateWalkthrough(context: $TSContext, lambdaToUpdate?: string) {
  const lambdaFuncResourceNames = ((await context.amplify.getResourceStatus()).allResources as $TSAny[])
    .filter(resource => resource.service === ServiceName.LambdaFunction && resource.mobileHubMigrated !== true)
    .map(resource => resource.resourceName);

  if (lambdaFuncResourceNames.length === 0) {
    context.print.error('No Lambda function resource to update. Use "amplify add function" to create a new function.');
    return;
  }

  if (lambdaToUpdate) {
    if (!lambdaFuncResourceNames.includes(lambdaToUpdate)) {
      context.print.error(`No Lambda function named ${lambdaToUpdate} exists in the project.`);
      return;
    }
  } else {
    const resourceQuestion = [
      {
        name: 'resourceName',
        message: 'Select the Lambda function you want to update',
        type: 'list',
        choices: lambdaFuncResourceNames,
      },
    ];
    lambdaToUpdate = (await inquirer.prompt(resourceQuestion)).resourceName as string;
  }

  // initialize function parameters for update
  const functionParameters: Partial<FunctionParameters> = {
    resourceName: lambdaToUpdate,
    environmentMap: {
      ENV: {
        Ref: 'env',
      },
      REGION: {
        Ref: 'AWS::Region',
      },
    },
  };

  const projectBackendDirPath = pathManager.getBackendDirPath();
  const resourceDirPath = path.join(projectBackendDirPath, categoryName, functionParameters.resourceName);
  const currentParameters = loadFunctionParameters(resourceDirPath);
  const functionRuntime = context.amplify.readBreadcrumbs(categoryName, functionParameters.resourceName).functionRuntime as string;

  const cfnParameters = JSONUtilities.readJson<$TSAny>(path.join(resourceDirPath, parametersFileName), { throwIfNotExist: false }) || {};
  const scheduleParameters = {
    cloudwatchRule: cfnParameters.CloudWatchRule,
    resourceName: functionParameters.resourceName,
  };

  await provideInformation(context, lambdaToUpdate, functionRuntime, currentParameters, scheduleParameters);

  // Determine which settings need to be updated
  const { selectedSettings }: $TSAny = await settingsUpdateSelection();

  if (selectedSettings.includes(resourceAccessSetting)) {
    const additionalParameters = await askExecRolePermissionsQuestions(context, lambdaToUpdate, currentParameters.permissions);
    additionalParameters.dependsOn = additionalParameters.dependsOn || [];
    merge(functionParameters, additionalParameters);
    updateCFNFileForResourcePermissions(resourceDirPath, functionParameters, currentParameters);
  }

  // ask scheduling Lambda questions and merge in results
  if (selectedSettings.includes(cronJobSetting)) {
    merge(functionParameters, await scheduleWalkthrough(context, scheduleParameters, true));
  }

  // ask lambdalayer questions and merge results
  if (selectedSettings.includes(lambdaLayerSetting)) {
    const currentFunctionParameters: $TSAny =
      JSONUtilities.readJson(path.join(resourceDirPath, functionParametersFileName), { throwIfNotExist: false }) || {};
    merge(
      functionParameters,
      await addLayersToFunctionWalkthrough(context, { value: functionRuntime }, currentFunctionParameters.lambdaLayers, true),
    );
    // writing to the CFN here because it's done above for the schedule and the permissions but we should really pull all of it into another function
    addLayerCFNParameters(context, functionParameters, resourceDirPath);
  }

  if (selectedSettings.includes(secretsConfiguration)) {
    merge(
      functionParameters,
      await secretValuesWalkthrough(secretNamesToSecretDeltas(getLocalFunctionSecretNames(functionParameters.resourceName)), {
        preConfirmed: true,
      }),
    );
  }

  // consolidate dependsOn as above logic is overwriting
  const projectMeta = stateManager.getMeta();
  functionParameters.dependsOn = consolidateDependsOnForLambda(projectMeta, functionParameters.dependsOn, lambdaToUpdate, selectedSettings);
  return functionParameters;
}

export function migrate(context: $TSContext, projectPath: string, resourceName: string) {
  const resourceDirPath = pathManager.getResourceDirectoryPath(projectPath, categoryName, resourceName);
  const cfnFilePath = path.join(resourceDirPath, `${resourceName}-cloudformation-template.json`);
  const oldCfn = JSONUtilities.readJson<$TSAny>(cfnFilePath);
  const newCfn: $TSAny = {};
  Object.assign(newCfn, oldCfn);

  // Add env parameter
  if (!newCfn.Parameters) {
    newCfn.Parameters = {};
  }
  newCfn.Parameters.env = {
    Type: 'String',
  };

  // Add conditions block
  if (!newCfn.Conditions) {
    newCfn.Conditions = {};
  }
  newCfn.Conditions.ShouldNotCreateEnvResources = {
    'Fn::Equals': [
      {
        Ref: 'env',
      },
      'NONE',
    ],
  };

  // Add if condition for resource name change
  const oldFunctionName = newCfn.Resources.LambdaFunction.Properties.FunctionName;

  newCfn.Resources.LambdaFunction.Properties.FunctionName = {
    'Fn::If': [
      'ShouldNotCreateEnvResources',
      oldFunctionName,
      {
        'Fn::Join': [
          '',
          [
            oldFunctionName,
            '-',
            {
              Ref: 'env',
            },
          ],
        ],
      },
    ],
  };

  newCfn.Resources.LambdaFunction.Properties.Environment = { Variables: { ENV: { Ref: 'env' } } };

  const oldRoleName = newCfn.Resources.LambdaExecutionRole.Properties.RoleName;

  newCfn.Resources.LambdaExecutionRole.Properties.RoleName = {
    'Fn::If': [
      'ShouldNotCreateEnvResources',
      oldRoleName,
      {
        'Fn::Join': [
          '',
          [
            oldRoleName,
            '-',
            {
              Ref: 'env',
            },
          ],
        ],
      },
    ],
  };

  JSONUtilities.writeJson(cfnFilePath, newCfn);
}

export function updateCFNFileForResourcePermissions(
  resourceDirPath: string,
  functionParameters: Partial<FunctionParameters>,
  currentParameters: $TSObject,
  apiResourceName?: string,
) {
  const cfnFileName = `${functionParameters.resourceName}-cloudformation-template.json`;
  const cfnFilePath = path.join(resourceDirPath, cfnFileName);
  const cfnContent = JSONUtilities.readJson<$TSAny>(cfnFilePath);
  const dependsOnParams = { env: { Type: 'String' } };

  Object.keys(functionParameters.environmentMap)
    .filter(key => key !== 'ENV')
    .filter(key => key !== 'REGION')
    .filter(resourceProperty => 'Ref' in functionParameters.environmentMap[resourceProperty])
    .forEach(resourceProperty => {
      dependsOnParams[functionParameters.environmentMap[resourceProperty].Ref] = {
        Type: 'String',
        Default: functionParameters.environmentMap[resourceProperty].Ref,
      };
    });

  cfnContent.Parameters = getNewCFNParameters(
    cfnContent.Parameters,
    currentParameters,
    dependsOnParams,
    functionParameters.mutableParametersState,
    apiResourceName,
  );

  if (!cfnContent.Resources.AmplifyResourcesPolicy) {
    cfnContent.Resources.AmplifyResourcesPolicy = {
      DependsOn: ['LambdaExecutionRole'],
      Type: 'AWS::IAM::Policy',
      Properties: {
        PolicyName: 'amplify-lambda-execution-policy',
        Roles: [
          {
            Ref: 'LambdaExecutionRole',
          },
        ],
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [],
        },
      },
    };
  }

  if (functionParameters.categoryPolicies.length === 0) {
    delete cfnContent.Resources.AmplifyResourcesPolicy;
  } else {
    cfnContent.Resources.AmplifyResourcesPolicy.Properties.PolicyDocument.Statement = functionParameters.categoryPolicies;
  }

  cfnContent.Resources.LambdaFunction.Properties.Environment.Variables = getNewCFNEnvVariables(
    cfnContent.Resources.LambdaFunction.Properties.Environment.Variables,
    currentParameters,
    functionParameters.environmentMap,
    functionParameters.mutableParametersState,
    apiResourceName,
  );

  JSONUtilities.writeJson(cfnFilePath, cfnContent);
  tryUpdateTopLevelComment(resourceDirPath, _.keys(functionParameters.environmentMap));
}

const addLayerCFNParameters = (context: $TSContext, functionParameters: Partial<FunctionParameters>, resourceDirPath: string) => {
  const cfnFileName = `${functionParameters.resourceName}-cloudformation-template.json`;
  const cfnFilePath = path.join(resourceDirPath, cfnFileName);
  const cfnContent = JSONUtilities.readJson<$TSAny>(cfnFilePath);
  functionParameters.lambdaLayers.forEach(layer => {
    const resourceName = _.get(layer as ProjectLayer, ['resourceName'], null);
    if (resourceName) {
      const param: string = `function${resourceName}Arn`;
      if (cfnContent.Parameters[param] === undefined) {
        cfnContent.Parameters[param] = {
          Type: 'String',
          Default: param,
        };
      }
    }
  });
  cfnContent.Resources.LambdaFunction.Properties.Layers = convertLambdaLayerMetaToLayerCFNArray(
    functionParameters.lambdaLayers,
    context.amplify.getEnvInfo().envName,
  );
  JSONUtilities.writeJson(cfnFilePath, cfnContent);
};
