import { ref } from 'vue'
export const authEnabled = ref(true)
export const authenticated = ref(false)
const savedToken = sessionStorage.getItem('hubproxy-token') || ''
export const activeToken = ref(isProxyToken(savedToken) ? savedToken : '')
if (savedToken && !isProxyToken(savedToken)) sessionStorage.removeItem('hubproxy-token')
export function isProxyToken(value: string): boolean {
  return /^[a-z2-7]{15}$/.test(value)
}
export function selectToken(value: string) {
  activeToken.value = value.trim()
  if (activeToken.value) sessionStorage.setItem('hubproxy-token', activeToken.value)
  else sessionStorage.removeItem('hubproxy-token')
}
export function proxyPath(path: string): string {
  if (!authEnabled.value) return path
  if (!isProxyToken(activeToken.value)) throw new Error('请先在令牌管理中创建或填入令牌')
  return `/${activeToken.value}${path}`
}
export function proxyHost(): string {
  return window.location.host + (authEnabled.value ? `/${activeToken.value || '<令牌>'}` : '')
}
export async function adminRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/admin/${path}`, {
    ...init, credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', 'X-Hubproxy-Admin': '1', ...init?.headers },
  })
  if (!res.ok) {
    if (res.status === 401) authenticated.value = false
    const data = await res.json().catch(() => ({}))
    throw new Error(data.error || `请求失败 (${res.status})`)
  }
  return res.status === 204 ? undefined as T : res.json()
}
export async function refreshSession() {
  const state = await adminRequest<{ enabled: boolean; authenticated: boolean }>('session')
  authEnabled.value = state.enabled
  authenticated.value = state.authenticated
}
