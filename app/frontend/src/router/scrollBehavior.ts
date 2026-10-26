import type { RouterScrollBehavior } from 'vue-router'

/** Source selection updates the URL within a task without moving the document. */
export const scrollBehavior: RouterScrollBehavior = (to, from, savedPosition) => {
  if (savedPosition) return savedPosition
  if (
    to.name === 'task-detail' &&
    from.name === 'task-detail' &&
    to.params.id === from.params.id
  ) return false
  return { top: 0 }
}
