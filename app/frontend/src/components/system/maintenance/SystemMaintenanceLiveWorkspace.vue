<script setup lang="ts">
import { onMounted } from 'vue'

import type { AuditLogListQuery } from '@/api/types'
import SystemStatusPanel from '@/components/system/SystemStatusPanel.vue'
import AnalyzerStatusPanel from '@/components/system/maintenance/AnalyzerStatusPanel.vue'
import AuditLogLivePanel from '@/components/system/maintenance/AuditLogLivePanel.vue'
import MaintenanceWorkspaceTabs from '@/components/system/maintenance/MaintenanceWorkspaceTabs.vue'
import LLMSettingsPanel from '@/components/system/maintenance/LLMSettingsPanel.vue'
import OperationalMetricsPanel from '@/components/system/maintenance/OperationalMetricsPanel.vue'
import { useAuditLogs } from '@/composables/useAuditLogs'
import { useSystemMaintenance } from '@/composables/useSystemMaintenance'

const system = useSystemMaintenance()
const audit = useAuditLogs()

function searchAudit(query: AuditLogListQuery): void {
  void audit.load(query)
}

function refreshAudit(): void {
  void audit.load(audit.query.value)
}

onMounted(() => {
  void system.load()
  void audit.load()
})
</script>

<template>
  <MaintenanceWorkspaceTabs>
    <template #runtime>
      <div class="runtime-workspace">
        <SystemStatusPanel
          managed
          :status="system.status.value"
          :loading="system.loading.value"
          :error-message="system.errorMessage.value"
          @retry="system.load"
        />
        <OperationalMetricsPanel
          v-if="system.status.value?.operational_metrics"
          :metrics="system.status.value.operational_metrics"
        />
      </div>
    </template>
    <template #analyzers>
      <AnalyzerStatusPanel
        :status="system.status.value"
        :loading="system.loading.value"
        :error-message="system.errorMessage.value"
        @retry="system.load"
      />
    </template>
    <template #llm>
      <LLMSettingsPanel />
    </template>
    <template #audit>
      <AuditLogLivePanel
        :logs="audit.logs.value"
        :loading="audit.loading.value"
        :loading-more="audit.loadingMore.value"
        :load-more-error="audit.loadMoreError.value"
        :error-message="audit.errorMessage.value"
        :has-more="Boolean(audit.nextCursor.value)"
        :exporting="audit.exporting.value"
        :export-error="audit.exportError.value"
        :export-feedback="audit.exportFeedback.value"
        @export="audit.exportLogs"
        @search="searchAudit"
        @retry="refreshAudit"
        @load-more="audit.load(audit.query.value, { append: true })"
      />
    </template>
  </MaintenanceWorkspaceTabs>
</template>

<style scoped>
.runtime-workspace {
  display: grid;
  min-width: 0;
  gap: 14px;
}
</style>
