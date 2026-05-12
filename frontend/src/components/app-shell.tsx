import {
  BarChart3,
  FileUp,
  FolderTree,
  LogOut,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react"
import type { ReactNode } from "react"

import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { ThemeModeToggle } from "@/components/theme-mode-toggle"
import type { ActorMetadata } from "@/lib/api"
import type { ThemeMode } from "@/lib/theme"
import { cn } from "@/lib/utils"

export type AppRoute = "overview" | "findings" | "inventory" | "imports" | "admin"

type AppShellProps = {
  activeRoute: AppRoute
  actor: ActorMetadata
  children: ReactNode
  isLoggingOut?: boolean
  themeMode: ThemeMode
  onNavigate: (route: AppRoute) => void
  onLogout: () => void
  onThemeModeChange: (mode: ThemeMode) => void
}

const navItems = [
  { label: "Overview", icon: BarChart3, route: "overview" as const, href: "/" },
  { label: "Findings", icon: ShieldCheck, route: "findings" as const, href: "/findings" },
  { label: "Inventory", icon: FolderTree, route: "inventory" as const, href: "/inventory" },
  { label: "Import Scans", icon: FileUp, route: "imports" as const, href: "/imports" },
  { label: "Admin", icon: SlidersHorizontal, route: "admin" as const, href: "/admin" },
]

export function appVersionLabel(version: string): string {
  return `v${version}`
}

export function AppShell({
  activeRoute,
  actor,
  children,
  isLoggingOut = false,
  onLogout,
  onNavigate,
  onThemeModeChange,
  themeMode,
}: AppShellProps) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="grid min-h-screen lg:grid-cols-[17rem_1fr]">
        <aside className="border-b bg-card px-4 py-4 lg:sticky lg:top-0 lg:flex lg:h-screen lg:flex-col lg:border-b-0 lg:border-r lg:px-5 lg:py-6">
          <div>
            <a className="block text-lg font-semibold tracking-normal" href="/">
              Dionysus
            </a>
            <p className="mt-1 text-xs text-muted-foreground">
              {appVersionLabel(__APP_VERSION__)}
            </p>
          </div>

          <Separator className="my-4 hidden lg:block" />

          <nav className="flex gap-2 overflow-x-auto lg:grid lg:overflow-visible">
            {navItems.map((item) => (
              <a
                aria-current={activeRoute === item.route ? "page" : undefined}
                className={cn(
                  "inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground",
                  activeRoute === item.route && "bg-accent text-accent-foreground",
                )}
                href={item.href}
                key={item.label}
                onClick={(event) => {
                  event.preventDefault()
                  onNavigate(item.route)
                }}
              >
                <item.icon className="size-4" aria-hidden="true" />
                <span>{item.label}</span>
              </a>
            ))}
          </nav>

          <div className="mt-4 border-t pt-4 lg:mt-auto lg:border-t-0 lg:pt-6">
            <ThemeModeToggle
              className="w-full"
              mode={themeMode}
              onModeChange={onThemeModeChange}
            />
            <div className="mt-4 flex items-center justify-between gap-3 lg:block">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{actor.display_name}</p>
              </div>
              <Button
                aria-label="Sign out"
                className="lg:mt-3 lg:w-full"
                disabled={isLoggingOut}
                onClick={onLogout}
                size="sm"
                type="button"
                variant="outline"
              >
                <LogOut className="size-4" aria-hidden="true" />
                <span>Sign out</span>
              </Button>
            </div>
          </div>
        </aside>

        <main className="min-w-0 px-5 py-5 lg:px-8 lg:py-7">{children}</main>
      </div>
    </div>
  )
}
