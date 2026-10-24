import { describe, expect, it } from 'vitest'
import { cpuBar, formatCpuPercent } from './cpuDisplay'

/**
 * `/system` 控制面卡片曾把已是百分比的 CPU 读数又乘 100，把 5% 显示成
 * "500.0%"。这两个纯函数是修复的落点：`formatCpuPercent` 只格式化不换算，
 * `cpuBar` 负责把越界值钳到进度条可用的 [0, 100]。
 */
describe('formatCpuPercent', () => {
  it('renders a percentage as-is without scaling it again', () => {
    // 后端口径是 0-100；5 必须显示成 5.0%，不能是 500.0%。
    expect(formatCpuPercent(5)).toBe('5.0%')
    expect(formatCpuPercent(5)).not.toBe('500.0%')
  })

  it('keeps one decimal place', () => {
    expect(formatCpuPercent(0)).toBe('0.0%')
    expect(formatCpuPercent(12.5)).toBe('12.5%')
    expect(formatCpuPercent(100)).toBe('100.0%')
  })

  it('renders a placeholder for a missing or unusable reading', () => {
    expect(formatCpuPercent(null)).toBe('—')
    expect(formatCpuPercent(Number.NaN)).toBe('—')
    expect(formatCpuPercent(Number.POSITIVE_INFINITY)).toBe('—')
  })
})

describe('cpuBar', () => {
  it('maps a percentage onto a 0-100% bar width', () => {
    expect(cpuBar(0)).toBe('0.0%')
    expect(cpuBar(12.5)).toBe('12.5%')
    expect(cpuBar(100)).toBe('100.0%')
  })

  /**
   * 进度条是最后一道防线：即便后端将来回退成单核口径（可到 400），
   * 条宽也不会溢出容器。
   */
  it('clamps a reading that overshoots the bar', () => {
    expect(cpuBar(400)).toBe('100.0%')
    expect(cpuBar(-5)).toBe('0.0%')
  })

  it('renders nothing for a missing reading', () => {
    expect(cpuBar(null)).toBeNull()
    expect(cpuBar(Number.NaN)).toBeNull()
  })
})
