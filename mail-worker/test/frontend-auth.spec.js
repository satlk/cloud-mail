import { it, expect, vi, beforeEach } from 'vitest';
vi.mock('@/router', () => ({ default: { replace: vi.fn() } }));
vi.mock('@/i18n/index.js', () => ({ default: { global: { t: key => key } } }));
vi.mock('@/store/setting.js', () => ({ useSettingStore: () => ({ lang: 'zh' }) }));
import router from '@/router';
import http from '../../mail-vue/src/axios/index.js';

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal('localStorage', { removeItem: vi.fn() });
  vi.stubGlobal('ElMessage', vi.fn());
  vi.stubGlobal('location', { reload: vi.fn() });
});
it('clears expired sessions and redirects even for silent polling requests', async () => {
  const body = { code: 401, message: 'Session expired' };
  const error = { response: { status: 401, data: body }, config: { noMsg: true } };
  await expect(http.interceptors.response.handlers[0].rejected(error)).rejects.toEqual(body);
  expect(localStorage.removeItem).toHaveBeenCalledWith('token');
  expect(router.replace).toHaveBeenCalledWith('/login');
});
it('rejects forbidden requests without a reload loop', async () => {
  const body = { code: 403, message: 'Forbidden' };
  await expect(http.interceptors.response.handlers[0].rejected({ response: { status: 403, data: body } })).rejects.toEqual(body);
  expect(location.reload).not.toHaveBeenCalled();
  expect(localStorage.removeItem).not.toHaveBeenCalled();
});
