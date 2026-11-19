export type ZscalerGuardMode = 'redact' | 'block' | 'off'

declare module 'claude-code' {
  interface PluginState {
    'zscaler-guard': {
      guardMode: ZscalerGuardMode
      tagSuffix: string
      incidents: number
      hidden: number
      withheld: number
    }
  }
}
