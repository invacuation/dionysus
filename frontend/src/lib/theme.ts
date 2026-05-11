export const THEME_MODE_STORAGE_KEY = "dionysus.themeMode"

export const themeModes = ["light", "dark", "system"] as const

export type ThemeMode = (typeof themeModes)[number]
export type ResolvedThemeMode = Exclude<ThemeMode, "system">

type ThemeModeReader = Pick<Storage, "getItem">
type ThemeModeWriter = Pick<Storage, "setItem">

export function isThemeMode(value: string | null): value is ThemeMode {
  return value === "light" || value === "dark" || value === "system"
}

export function loadThemeMode(storage: ThemeModeReader): ThemeMode {
  try {
    const storedMode = storage.getItem(THEME_MODE_STORAGE_KEY)
    return isThemeMode(storedMode) ? storedMode : "system"
  } catch {
    return "system"
  }
}

export function storeThemeMode(storage: ThemeModeWriter, mode: ThemeMode) {
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
