import { fleetApi } from './fleet';
import { ApiError, getBasePath, serverHttp, setOnUnauthorized } from './http';
import { overviewApi } from './overview';
import { securityApi } from './security';
import { servicesApi } from './services';
import { subscriptionsApi } from './subscriptions';
import { warpApi } from './warp';

export {
  ApiError,
  getBasePath,
  serverHttp,
  setOnUnauthorized,
  overviewApi,
  servicesApi,
  subscriptionsApi,
  warpApi,
  fleetApi,
  securityApi,
};

export const api = {
  ...overviewApi,
  ...servicesApi,
  ...subscriptionsApi,
  ...warpApi,
  ...fleetApi,
  ...securityApi,
};
