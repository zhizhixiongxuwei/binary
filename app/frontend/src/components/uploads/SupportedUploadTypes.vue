<script setup lang="ts">
import { Archive, Box, CodeXml } from 'lucide-vue-next'
import { computed } from 'vue'

import type { InputCategory } from '@/api/types'

const props = defineProps<{
  category?: InputCategory
}>()

const groups = [
  {
    category: 'binary',
    icon: CodeXml,
    title: '反编译分析',
    formats: 'EXE、DLL、SYS、ELF、Mach-O、CLASS、JAR、WAR、EAR、DEX、APK、PYC',
  },
  {
    category: 'archive',
    icon: Archive,
    title: '归档导入',
    formats:
      'ZIP、7Z、RAR、TAR、GZIP、XZ、DEB、RPM、ISO、EXT4、JAR、APK',
  },
  {
    category: 'container',
    icon: Box,
    title: '容器/映像分析',
    formats:
      'Docker/OCI TAR（可使用 .tar / .img）；ISO、EXT4 选择归档模式，Trivy 不适用',
  },
] as const

const visibleGroups = computed(() =>
  props.category
    ? groups.filter((group) => group.category === props.category)
    : groups,
)
</script>

<template>
  <div
    class="supported-types"
    :class="{ 'supported-types--single': category }"
    aria-label="支持的检测文件类型"
  >
    <div
      v-for="group in visibleGroups"
      :key="group.category"
      class="supported-types__group"
    >
      <component :is="group.icon" :size="17" aria-hidden="true" />
      <div>
        <strong>{{ group.title }}</strong>
        <p>{{ group.formats }}</p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.supported-types {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0;
  margin-bottom: 14px;
  border-block: 1px solid var(--line);
  background: var(--surface-raised);
}

.supported-types--single {
  grid-template-columns: 1fr;
}

.supported-types__group {
  display: grid;
  min-width: 0;
  grid-template-columns: 24px minmax(0, 1fr);
  gap: 8px;
  padding: 12px 14px;
  color: var(--primary-hover);
}

.supported-types__group + .supported-types__group {
  border-left: 1px solid var(--line);
}

.supported-types__group svg {
  margin-top: 1px;
}

.supported-types__group strong,
.supported-types__group p {
  display: block;
  margin: 0;
}

.supported-types__group strong {
  color: var(--ink-800);
  font-size: 12px;
}

.supported-types__group p {
  margin-top: 3px;
  color: var(--ink-800);
  font-size: 12px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

@media (max-width: 700px) {
  .supported-types {
    grid-template-columns: 1fr;
  }

  .supported-types__group + .supported-types__group {
    border-top: 1px solid var(--line);
    border-left: 0;
  }
}
</style>
