<script setup lang="ts">
import { ref } from 'vue'
import { adminRequest, authenticated } from '@/auth'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
const password = ref('')
const error = ref('')
const busy = ref(false)
async function login() {
  busy.value = true; error.value = ''
  try {
    await adminRequest('login', { method: 'POST', body: JSON.stringify({ password: password.value }) })
    password.value = ''; authenticated.value = true
  } catch (e) { error.value = (e as Error).message }
  finally { busy.value = false }
}
</script>
<template>
  <section class="surface-panel mx-auto max-w-md space-y-6 p-7">
    <div><h1 class="font-display text-2xl font-semibold">登录 HubProxy</h1><p class="mt-2 text-muted-foreground">登录后创建代理令牌，设置首次使用后的有效时长。</p></div>
    <form class="space-y-4" @submit.prevent="login">
      <label class="block space-y-2"><span>管理员密码</span><Input v-model="password" type="password" autocomplete="current-password" required /></label>
      <p v-if="error" role="alert" class="text-destructive">{{ error }}</p>
      <Button type="submit" :disabled="busy" class="w-full">{{ busy ? '正在登录…' : '登录' }}</Button>
    </form>
  </section>
</template>
