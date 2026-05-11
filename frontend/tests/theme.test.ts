import { describe, expect, test } from "bun:test"

import {
  applyThemeMode,
  loadThemeMode,
  resolveThemeMode,
  safeThemeModeStorage,
  storeThemeMode,
  THEME_MODE_STORAGE_KEY,
  type ThemeMode,
} from "../src/lib/theme"

function documentElementWithClasses(...classNames: string[]) {
  return {
    classList: {
      values: new Set(classNames),
      add(className: string) {
        this.values.add(className)
      },
      remove(className: string) {
        this.values.delete(className)
      },
      contains(className: string) {
        return this.values.has(className)
      },
    },
  }
}

describe("theme mode persistence", () => {
  test("treats blocked storage access as unavailable", () => {
    expect(
      safeThemeModeStorage(() => {
        throw new DOMException("Access denied", "SecurityError")
      }),
    ).toBeNull()
  })

  test("defaults to system mode when no valid preference is stored", () => {
    expect(loadThemeMode({ getItem: () => null })).toBe("system")
    expect(loadThemeMode({ getItem: () => "dim" })).toBe("system")
    expect(loadThemeMode(null)).toBe("system")
  })

  test("stores the selected mode outside of authentication state", () => {
    const storage = new Map<string, string>()

    storeThemeMode(
      {
        setItem(key, value) {
          storage.set(key, value)
        },
      },
      "dark",
    )

    expect(storage.get(THEME_MODE_STORAGE_KEY)).toBe("dark")
  })
})

describe("theme mode resolution", () => {
  test.each([
    ["light", true, false],
    ["dark", false, true],
    ["system", true, true],
    ["system", false, false],
  ] satisfies Array<[ThemeMode, boolean, boolean]>)(
    "resolves %s mode with system dark=%p",
    (mode, systemPrefersDark, expectedDark) => {
      expect(resolveThemeMode(mode, systemPrefersDark)).toBe(expectedDark ? "dark" : "light")
    },
  )

  test("applies the dark class only when the resolved mode is dark", () => {
    const root = documentElementWithClasses("dark")

    applyThemeMode(root, "light")
    expect(root.classList.contains("dark")).toBe(false)

    applyThemeMode(root, "dark")
    expect(root.classList.contains("dark")).toBe(true)
  })
})
