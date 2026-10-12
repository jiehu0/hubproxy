<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { authEnabled, authenticated, refreshSession } from '@/auth'
import LoginForm from '@/components/LoginForm.vue'
import { RouterView } from 'vue-router'
import AppShell from '@/components/AppShell.vue'
const ready = ref(false)
const error = ref('')
onMounted(async () => { try { await refreshSession(); ready.value = true } catch { error.value = '无法连接服务，请刷新重试' } })
</script>

<template>
  <AppShell>
    <p v-if="error" role="alert" class="text-center text-destructive">{{ error }}</p>
    <p v-else-if="!ready" class="text-center">正在连接…</p>
    <LoginForm v-else-if="authEnabled && !authenticated" />
    <RouterView v-else v-slot="{ Component, route }">
      <Transition name="page">
        <component :is="Component" :key="route.path" />
      </Transition>
    </RouterView>
  </AppShell>
</template>
