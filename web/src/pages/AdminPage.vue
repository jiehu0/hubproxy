<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { activeToken, adminRequest, authenticated, isProxyToken, selectToken } from '@/auth'
import { copyText } from '@/lib/utils'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
interface Token { id: string; name: string; duration_seconds: number; created_at: string; activated_at: string | null; expires_at: string | null }
const host = location.host
const tokens = ref<Token[]>([])
const name = ref('')
const minutes = ref('60')
const secret = ref('')
const restored = ref(activeToken.value)
const error = ref('')
const busy = ref(false)
const copied = ref(false)
const now = ref(Date.now())
const base = computed(() => `${location.origin}/${secret.value}`)
let timer: ReturnType<typeof setInterval> | undefined
async function reload() {
  try { tokens.value = await adminRequest<Token[]>('tokens') }
  catch (e) { error.value = (e as Error).message }
}
async function create() {
  busy.value = true; error.value = ''; copied.value = false
  try {
    const data = await adminRequest<{ secret: string }>('tokens', { method: 'POST', body: JSON.stringify({ name: name.value, duration_seconds: Math.round(Number(minutes.value) * 60) }) })
    secret.value = data.secret; restored.value = data.secret; selectToken(data.secret); name.value = ''
    await reload()
  } catch (e) { error.value = (e as Error).message }
  finally { busy.value = false }
}
async function remove(id: string) {
  error.value = ''
  try { await adminRequest(`tokens/${id}`, { method: 'DELETE' }); await reload() }
  catch (e) { error.value = (e as Error).message }
}
async function logout() {
  try { await adminRequest('logout', { method: 'POST' }); selectToken(''); authenticated.value = false }
  catch (e) { error.value = (e as Error).message }
}
function useSaved() {
  if (!isProxyToken(restored.value.trim())) { error.value = '请输入完整的 26 位令牌（也支持旧版 64 位令牌）'; return }
  selectToken(restored.value); error.value = ''
}
function status(token: Token) {
  if (!token.expires_at) return '尚未使用'
  const left = Date.parse(token.expires_at) - now.value
  return left <= 0 ? '已过期' : `剩余 ${Math.ceil(left / 60000)} 分钟`
}
onMounted(() => { void reload(); timer = setInterval(() => { now.value = Date.now(); void reload() }, 15000) })
onUnmounted(() => clearInterval(timer))
</script>
<template>
  <div class="mx-auto max-w-4xl space-y-7">
    <div class="flex items-start justify-between gap-4"><div><h1 class="font-display text-3xl font-semibold">代理令牌</h1><p class="mt-2 text-muted-foreground">首次使用开始计时，到期自动失效。复制网址不会开始计时。</p></div><Button class="shrink-0 whitespace-nowrap" variant="secondary" @click="logout">退出登录</Button></div>
    <p v-if="error" role="alert" class="text-destructive">{{ error }}</p>
    <form class="surface-panel space-y-4 p-6" @submit.prevent="create">
      <h2 class="text-lg font-semibold">创建令牌</h2>
      <div class="grid gap-4 sm:grid-cols-2"><label class="space-y-2"><span>名称（可选）</span><Input v-model="name" maxlength="40" placeholder="例如：服务器下载" /></label><label class="space-y-2"><span>有效时长（分钟）</span><Input v-model="minutes" type="number" min="1" max="43200" step="1" required /></label></div>
      <p class="text-sm text-muted-foreground">默认 60 分钟，可设为 1 分钟至 30 天；有效期内不限请求次数，支持分层下载和重试。</p>
      <Button type="submit" :disabled="busy">{{ busy ? '正在创建…' : '创建令牌' }}</Button>
    </form>
    <section v-if="secret" class="surface-panel space-y-4 border-primary/40 p-6">
      <h2 class="text-lg font-semibold">专属代理地址</h2><p class="text-sm text-muted-foreground">令牌只在创建时显示，请保存。已自动用于本站的链接生成和下载。</p>
      <code class="block break-all rounded-lg bg-muted p-3">{{ base }}</code>
      <Button variant="secondary" @click="async () => { copied = await copyText(base) }">{{ copied ? '已复制' : '复制代理地址' }}</Button>
      <div class="space-y-2 text-sm"><p>文件下载：在此地址后追加原始链接。</p><code class="block break-all">{{ base }}/https://github.com/用户/仓库/releases/…</code><p>Docker 拉取：</p><code class="block break-all">docker pull {{ host }}/{{ secret }}/library/nginx:latest</code></div>
    </section>
    <details class="surface-panel space-y-3 p-5"><summary class="cursor-pointer">使用已保存的令牌</summary><label class="block"><span class="sr-only">已保存的令牌</span><Input v-model="restored" type="password" autocomplete="off" placeholder="粘贴令牌（兼容旧版）" /></label><Button variant="secondary" @click="useSaved">用于本站下载</Button></details>
    <section class="surface-panel overflow-x-auto p-6">
      <div class="mb-4 flex justify-between"><h2 class="text-lg font-semibold">令牌记录</h2><Button variant="ghost" size="sm" @click="reload">刷新</Button></div>
      <p v-if="!tokens.length" class="text-muted-foreground">尚未创建令牌。</p>
      <table v-else class="w-full min-w-[570px] text-left text-sm"><thead><tr class="border-b border-border"><th class="pb-3">名称</th><th class="pb-3">时长</th><th class="pb-3">状态</th><th class="pb-3">到期时间</th><th class="pb-3">操作</th></tr></thead><tbody><tr v-for="token in tokens" :key="token.id" class="border-b border-border/50"><td class="py-4">{{ token.name || '未命名' }}</td><td>{{ token.duration_seconds / 60 }} 分钟</td><td>{{ status(token) }}</td><td>{{ token.expires_at ? new Date(token.expires_at).toLocaleString() : '首次使用后确定' }}</td><td><Button variant="ghost" size="sm" @click="remove(token.id)">删除并失效</Button></td></tr></tbody></table>
    </section>
    <p class="text-sm text-muted-foreground">首次下载请求（包括 Docker 的 HEAD 探测或离线包准备请求）启动计时；到期后拒绝新请求，已经开始的传输允许完成。</p>
  </div>
</template>
