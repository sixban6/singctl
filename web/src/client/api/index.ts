import { ApiError } from '../../lib/http';
import { actionStreamApi } from './actionStream';
import { auditApi } from './audit';
import { dnsApi } from './dns';
import { networkApi } from './network';
import {
  CLIENT_AUTH_EVENT,
  clearSavedClientToken,
  clientHttp,
  getSavedClientToken,
  saveClientToken,
} from './session';
import { singboxApi } from './singbox';
import { systemApi } from './system';

export {
  ApiError,
  CLIENT_AUTH_EVENT,
  clearSavedClientToken,
  clientHttp,
  getSavedClientToken,
  saveClientToken,
  systemApi,
  singboxApi,
  dnsApi,
  auditApi,
  networkApi,
  actionStreamApi,
};

export const clientApi = {
  ...systemApi,
  ...singboxApi,
  ...dnsApi,
  ...auditApi,
  ...networkApi,
  ...actionStreamApi,
};
