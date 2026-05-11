export const THEME_MODE_STORAGE_KEY = "dionysus.themeMode"

export const themeModes = ["light", "dark", "system"] as const

export type ThemeMode = (typeof themeModes)[number]
export type ResolvedThemeMode = Exclude<ThemeMode, "system">

type ThemeModeReader = Pick<Storage, "getItem">
type ThemeModeWriter = Pick<Storage, "setItem">
type ThemeModeStorage = ThemeModeReader & ThemeModeWriter
type SystemThemeMediaQuery = Pick<MediaQueryList, "matches"> &
  Partial<Pick<MediaQueryList, "addEventListener" | "removeEventListener" | "addListener" | "removeListener">>

export function isThemeMode(value: string | null): value is ThemeMode {
  return value === "light" || value === "dark" || value === "system"
}

export function safeThemeModeStorage(readStorage: () => Storage): ThemeModeStorage | null {
  try {
    return readStorage()
  } catch {
    return null
  }
}

export function loadThemeMode(storage: ThemeModeReader | null): ThemeMode {
  if (!storage) {
    return "system"
  }

  try {
    const storedMode = storage.getItem(THEME_MODE_STORAGE_KEY)
    return isThemeMode(storedMode) ? storedMode : "system"
  } catch {
    return "system"
  }
}

export function storeThemeMode(storage: ThemeModeWriter | null, mode: ThemeMode) {
  if (!storage) {
    return
  }

  try {
    storage.setItem(THEME_MODE_STORAGE_KEY, mode)
  } catch {
    // Ignore unavailable storage; the selected mode still applies for this session.
  }
}

export function resolveThemeMode(
  mode: ThemeMode,
  systemPrefersDark: boolean,
): ResolvedThemeMode {
  if (mode === "system") {
    return systemPrefersDark ? "dark" : "light"
  }
  return mode
}

export function applyThemeMode(
  root: { classList: Pick<DOMTokenList, "add" | "remove"> },
  resolvedMode: ResolvedThemeMode,
) {
  if (resolvedMode === "dark") {
    root.classList.add("dark")
  } else {
    root.classList.remove("dark")
  }
}

export function observeSystemTheme(
  mediaQuery: SystemThemeMediaQuery,
  onChange: (systemPrefersDark: boolean) => void,
): () => void {
  const handleChange = () => onChange(mediaQuery.matches)

  handleChange()

  if (mediaQuery.addEventListener && mediaQuery.removeEventListener) {
    mediaQuery.addEventListener("change", handleChange)
    return () => mediaQuery.removeEventListener?.("change", handleChange)
  }

  mediaQuery.addListener?.(handleChange)
  return () => mediaQuery.removeListener?.(handleChange)
}
