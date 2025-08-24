/**
 * Performance Mode Auto-Detection Types
 * Defines types for intelligent performance optimization system
 */

/**
 * Performance rendering modes
 */
export type PerformanceMode = 
  | 'normal'        // Standard rendering for small datasets
  | 'advisory'      // Show performance advisory banner
  | 'pagination'    // Paginated view for medium datasets
  | 'virtualized'   // Virtualized rendering for large datasets

/**
 * Performance thresholds configuration
 */
export interface PerformanceThresholds {
  /** Show advisory banner at this count */
  advisory: number
  /** Prompt for pagination at this count */
  pagination: number
  /** Auto-switch to virtualization at this count */
  virtualization: number
  /** Memory usage threshold in bytes */
  memoryThreshold: number
}

/**
 * Performance preferences for user control
 */
export interface PerformancePreferences {
  /** Enable automatic performance mode detection */
  autoDetection: boolean
  /** Force disable virtualization */
  forceDisableVirtualization: boolean
  /** Force enable pagination */
  forceEnablePagination: boolean
  /** Custom thresholds override */
  customThresholds?: Partial<PerformanceThresholds>
  /** Preferred page size for pagination */
  pageSize: number
  /** Enable performance monitoring */
  enableMonitoring: boolean
}

/**
 * Performance metrics tracking
 */
export interface PerformanceMetrics {
  /** Current memory usage in bytes */
  memoryUsage: number
  /** Current dataset size */
  datasetSize: number
  /** Current rendering mode */
  currentMode: PerformanceMode
  /** Last render time in milliseconds */
  lastRenderTime: number
  /** Average render time over last 10 renders */
  averageRenderTime: number
  /** Memory usage trend (increasing/decreasing/stable) */
  memoryTrend: 'increasing' | 'decreasing' | 'stable'
  /** Performance score (0-100) */
  performanceScore: number
}

/**
 * Performance state interface
 */
export interface PerformanceState {
  /** Current performance mode */
  mode: PerformanceMode
  /** Performance metrics */
  metrics: PerformanceMetrics
  /** User preferences */
  preferences: PerformancePreferences
  /** Whether advisory banner is shown */
  showAdvisoryBanner: boolean
  /** Whether pagination prompt is shown */
  showPaginationPrompt: boolean
  /** Current page for pagination mode */
  currentPage: number
  /** Whether performance monitoring is active */
  isMonitoring: boolean
  /** Last mode change timestamp */
  lastModeChange: number
}

/**
 * Performance actions interface
 */
export interface PerformanceActions {
  /** Update performance preferences */
  updatePreferences: (preferences: Partial<PerformancePreferences>) => void
  /** Manually set performance mode */
  setMode: (mode: PerformanceMode) => void
  /** Dismiss advisory banner */
  dismissAdvisoryBanner: () => void
  /** Accept pagination prompt */
  acceptPagination: () => void
  /** Decline pagination prompt */
  declinePagination: () => void
  /** Set current page for pagination */
  setCurrentPage: (page: number) => void
  /** Start performance monitoring */
  startMonitoring: () => void
  /** Stop performance monitoring */
  stopMonitoring: () => void
  /** Reset performance state */
  resetPerformance: () => void
}

/**
 * Performance context type
 */
export type PerformanceContextType = PerformanceState & PerformanceActions

/**
 * Virtualization configuration
 */
export interface VirtualizationConfig {
  /** Height of each row in pixels */
  rowHeight: number
  /** Height of the virtualized container */
  containerHeight: number
  /** Number of items to render outside visible area */
  overscanCount: number
  /** Enable horizontal scrolling */
  enableHorizontalScroll: boolean
}

/**
 * Pagination configuration
 */
export interface PaginationConfig {
  /** Items per page */
  pageSize: number
  /** Show page size selector */
  showPageSizeSelector: boolean
  /** Available page sizes */
  pageSizeOptions: number[]
  /** Show quick jump to page */
  showQuickJump: boolean
}

/**
 * Performance advisory banner configuration
 */
export interface AdvisoryBannerConfig {
  /** Banner message */
  message: string
  /** Banner type */
  type: 'info' | 'warning' | 'error'
  /** Show dismiss button */
  dismissible: boolean
  /** Auto-dismiss after timeout */
  autoDissmissTimeout?: number
  /** Available actions */
  actions: Array<{
    label: string
    action: () => void
    variant?: 'primary' | 'secondary'
  }>
}

/**
 * Default performance configuration
 */
export const DEFAULT_PERFORMANCE_THRESHOLDS: PerformanceThresholds = {
  advisory: 1000,
  pagination: 2500,
  virtualization: 5000,
  memoryThreshold: 500 * 1024 * 1024, // 500MB
}

export const DEFAULT_PERFORMANCE_PREFERENCES: PerformancePreferences = {
  autoDetection: true,
  forceDisableVirtualization: false,
  forceEnablePagination: false,
  pageSize: 50,
  enableMonitoring: true,
}

export const DEFAULT_VIRTUALIZATION_CONFIG: VirtualizationConfig = {
  rowHeight: 60,
  containerHeight: 600,
  overscanCount: 5,
  enableHorizontalScroll: true,
}

export const DEFAULT_PAGINATION_CONFIG: PaginationConfig = {
  pageSize: 50,
  showPageSizeSelector: true,
  pageSizeOptions: [25, 50, 100, 200],
  showQuickJump: true,
}
