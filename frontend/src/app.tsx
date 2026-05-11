import { useEffect, useLayoutEffect, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { AppShell, type AppRoute } from "@/components/app-shell"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { AdminPage } from "@/features/admin/admin-page"
import { LoginPage } from "@/features/auth/login-page"
import { FindingsPage } from "@/features/findings/findings-page"
import { ImportsPage } from "@/features/imports/imports-page"
import { InventoryPage } from "@/features/inventory/inventory-page"
import { OverviewPage } from "@/features/overview/overview-page"
import { ApiError, getCurrentActor, login, logout } from "@/lib/api"
import {
  applyThemeMode,
  loadThemeMode,
  observeSystemTheme,
  resolveThemeMode,
  safeThemeModeStorage,
  storeThemeMode,
  type ThemeMode,
} from "@/lib/theme"

const currentActorQueryKey = ["auth", "me"] as const

export function App() {
  const queryClient = useQueryClient()
  const [activeRoute, setActiveRoute] = useState<AppRoute>(() => routeFromLocation())
  const [themeStorage] = useState(() => safeThemeModeStorage(() => window.localStorage))
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => loadThemeMode(themeStorage))
  const [systemPrefersDark, setSystemPrefersDark] = useState(() => getSystemPrefersDark())
  const currentActorQuery = useQuery({
    queryKey: currentActorQueryKey,
    queryFn: getCurrentActor,
    retry: (failureCount, error) =>
      !(error instanceof ApiError && error.status === 401) && failureCount < 1,
  })

  const loginMutation = useMutation({
    mutationFn: login,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: currentActorQueryKey })
    },
  })

  const logoutMutation = useMutation({
    mutationFn: logout,
    onSuccess: () => {
      queryClient.setQueryData(currentActorQueryKey, null)
      queryClient.removeQueries({ queryKey: ["overview"] })
      queryClient.removeQueries({ queryKey: ["findings"] })
      queryClient.removeQueries({ queryKey: ["projects"] })
      queryClient.removeQueries({ queryKey: ["audit-log"] })
      queryClient.removeQueries({ queryKey: ["machine-credentials"] })
    },
  })

  useEffect(() => {
    const handleNavigation = () => setActiveRoute(routeFromLocation())
    window.addEventListener("popstate", handleNavigation)
    return () => window.removeEventListener("popstate", handleNavigation)
  }, [])

  useEffect(() => {
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)")
    return observeSystemTheme(mediaQuery, setSystemPrefersDark)
  }, [])

  useLayoutEffect(() => {
    applyThemeMode(document.documentElement, resolveThemeMode(themeMode, systemPrefersDark))
  }, [systemPrefersDark, themeMode])

  function navigate(route: AppRoute) {
    const path = routePath(route)
    window.history.pushState({}, "", path)
    setActiveRoute(route)
  }

  function changeThemeMode(mode: ThemeMode) {
    setThemeMode(mode)
    storeThemeMode(themeStorage, mode)
  }

  if (currentActorQuery.isPending) {
    return (
      <main className="grid min-h-screen place-items-center bg-background px-5 text-sm text-muted-foreground">
        Loading...
      </main>
    )
  }

  const sessionError = currentActorQuery.error
  const isUnauthorized =
    sessionError instanceof ApiError && sessionError.status === 401

  if (currentActorQuery.isError && !isUnauthorized) {
    return (
      <main className="grid min-h-screen place-items-center bg-background px-5 text-foreground">
        <Card className="w-full max-w-sm">
          <CardHeader>
            <CardTitle className="text-base">Unable to check session</CardTitle>
            <CardDescription>
              {sessionError?.message ?? "The backend API did not return session data."}
            </CardDescription>
          </CardHeader>
        </Card>
      </main>
    )
  }

  if (isUnauthorized || !currentActorQuery.data) {
    return (
      <LoginPage
        error={loginMutation.error ? loginMutation.error.message : null}
        isSubmitting={loginMutation.isPending}
        themeMode={themeMode}
        onThemeModeChange={changeThemeMode}
        onSubmit={(credentials) => loginMutation.mutate(credentials)}
      />
    )
  }

  return (
    <AppShell
      activeRoute={activeRoute}
      actor={currentActorQuery.data}
      isLoggingOut={logoutMutation.isPending}
      themeMode={themeMode}
      onNavigate={navigate}
      onLogout={() => logoutMutation.mutate()}
      onThemeModeChange={changeThemeMode}
    >
      {activeRoute === "findings" ? (
        <FindingsPage currentActor={currentActorQuery.data} />
      ) : activeRoute === "inventory" ? (
        <InventoryPage />
      ) : activeRoute === "imports" ? (
        <ImportsPage />
      ) : activeRoute === "admin" ? (
        <AdminPage />
      ) : (
        <OverviewPage />
      )}
    </AppShell>
  )
}

function routeFromLocation(): AppRoute {
  if (window.location.pathname.startsWith("/findings")) {
    return "findings"
  }
  if (window.location.pathname.startsWith("/imports")) {
    return "imports"
  }
  if (window.location.pathname.startsWith("/inventory")) {
    return "inventory"
  }
  if (window.location.pathname.startsWith("/admin")) {
    return "admin"
  }
  return "overview"
}

function routePath(route: AppRoute): string {
  if (route === "findings") {
    return "/findings"
  }
  if (route === "imports") {
    return "/imports"
  }
  if (route === "inventory") {
    return "/inventory"
  }
  if (route === "admin") {
    return "/admin"
  }
  return "/"
}

function getSystemPrefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches
}
