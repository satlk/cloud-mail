<template>
  <!-- Same-origin retains authenticated inline images; scripts stay disabled by sandbox and CSP. -->
  <iframe class="content-html" title="邮件正文" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
    referrerpolicy="no-referrer" :srcdoc="documentHtml"></iframe>
</template>

<script setup>
import { computed } from 'vue'
import { sanitizeEmailHtml } from '@/utils/email-html'

const props = defineProps({ html: { type: String, required: true } })
const documentHtml = computed(() => {
  const clean = sanitizeEmailHtml(props.html)
  return `<!doctype html><html><head><meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src https: data: blob:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-src 'none'">
    <base target="_blank"><style>body{font:14px/1.5 sans-serif;overflow-wrap:anywhere;margin:8px}img{max-width:100%;height:auto}a{color:#0e70df}</style>
    </head><body>${clean}</body></html>`
})
</script>

<style scoped>
.content-html { display: block; width: 100%; height: 65vh; min-height: 320px; border: 0; background: white; }
</style>
