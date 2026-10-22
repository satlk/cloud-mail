import DOMPurify from 'dompurify'

// Shared by the reader, drafts, replies and forwarding before HTML reaches a DOM/editor.
export function sanitizeEmailHtml(html) {
  return DOMPurify.sanitize(html || '', {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ['form', 'input', 'button', 'textarea', 'select', 'style', 'link', 'meta', 'base'],
    FORBID_ATTR: ['srcset', 'ping', 'autofocus'],
    ADD_ATTR: ['target']
  })
}
