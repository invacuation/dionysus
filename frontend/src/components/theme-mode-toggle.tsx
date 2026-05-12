import { Monitor, Moon, Sun } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { themeModes, type ThemeMode } from "@/lib/theme"

type ThemeModeToggleProps = {
  mode: ThemeMode
  onModeChange: (mode: ThemeMode) => void
  className?: string
}

const themeModeLabels: Record<ThemeMode, string> = {
  light: "Light",
  dark: "Dark",
  system: "System",
}

const themeModeIcons = {
  light: Sun,
  dark: Moon,
  system: Monitor,
} satisfies Record<ThemeMode, typeof Sun>

export function ThemeModeToggle({ className, mode, onModeChange }: ThemeModeToggleProps) {
  return (
    <div
      aria-label="Color theme"
      className={cn(
        "grid w-full min-w-0 grid-cols-3 gap-1 overflow-hidden rounded-md border bg-background p-1",
        className,
      )}
      role="group"
    >
      {themeModes.map((themeMode) => {
        const Icon = themeModeIcons[themeMode]
        const isSelected = mode === themeMode

        return (
          <Button
            aria-pressed={isSelected}
            className={cn(
              "h-8 min-w-0 justify-center gap-1 overflow-hidden px-1 text-[11px]",
              isSelected && "bg-accent text-accent-foreground",
            )}
            key={themeMode}
            onClick={() => onModeChange(themeMode)}
            size="sm"
            title={`${themeModeLabels[themeMode]} theme`}
            type="button"
            variant="ghost"
          >
            <Icon className="size-3.5 shrink-0" aria-hidden="true" />
            <span className="min-w-0 truncate">{themeModeLabels[themeMode]}</span>
          </Button>
        )
      })}
    </div>
  )
}
