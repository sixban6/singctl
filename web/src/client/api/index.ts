import { ApiError } from '../../lib/http';
import { actionStreamApi } from './actionStream';
import { auditApi } from './audit';
import { dnsApi } from './dns';
import { networkApi } from './network';
import { p0Api } from './p0';
import {
  CLIENT_AUTH_EVENT,
  clearSavedClientToken,
  clientHttp,
  getSavedClientToken,
  saveClientToken,
} from './session';
import { singboxApi } from './singbox';
import { systemApi } from './system';
import { vlanApi } from './vlan';
import { homeDomainApi } from './homedomain';
import { wifiApi } from './wifi';

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
  p0Api,
  vlanApi,
  homeDomainApi,
  wifiApi,
  actionStreamApi,
};

export const clientApi = {
  ...systemApi,
  ...singboxApi,
  ...dnsApi,
  ...auditApi,
  ...networkApi,
  ...p0Api,
  ...vlanApi,
  ...homeDomainApi,
  ...wifiApi,
  ...actionStreamApi,
};
