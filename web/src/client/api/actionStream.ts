import { ActionStreamEvent } from '../types';
import { clientHttp } from './session';

export const actionStreamApi = {
  async runActionStream(
    name: string,
    params: Record<string, unknown>,
    onEvent: (ev: ActionStreamEvent) => void,
  ): Promise<{ code: number; restarting: boolean; tailscaleSwapping: boolean }> {
    let exitCode = 0;
    let restarting = false;
    let tailscaleSwapping = false;

    await clientHttp.requestNDJSON<ActionStreamEvent>(
      '/api/action',
      {
        method: 'POST',
        body: JSON.stringify({ name, params }),
        statusErrorMessages: {
          409: '已有任务在执行中，请稍候',
        },
        formatHttpError: (status, jsonError) => jsonError || `HTTP ${status}`,
      },
      (ev) => {
        onEvent(ev);
        if (ev.t === 'exit') {
          exitCode = ev.code ?? 0;
          restarting = Boolean(ev.restarting);
          tailscaleSwapping = Boolean(ev.tailscaleSwapping);
        }
      },
    );

    return { code: exitCode, restarting, tailscaleSwapping };
  },
};
