import { FormEvent, useState } from "react"
import { AlertCircle, Loader2 } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { ThemeModeToggle } from "@/components/theme-mode-toggle"
import { Input } from "@/components/ui/input"
import type { ThemeMode } from "@/lib/theme"

type LoginPageProps = {
  error?: string | null
  isSubmitting: boolean
  themeMode: ThemeMode
  onThemeModeChange: (mode: ThemeMode) => void
  onSubmit: (credentials: { username: string; password: string }) => void
}

export function LoginPage({
  error,
  isSubmitting,
  onSubmit,
  onThemeModeChange,
  themeMode,
}: LoginPageProps) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const errorId = "login-error"

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    onSubmit({ username, password })
  }

  return (
    <main className="grid min-h-screen place-items-center bg-background px-5 py-8 text-foreground">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="flex flex-col gap-4">
            <CardTitle className="text-xl">Sign in</CardTitle>
            <ThemeModeToggle mode={themeMode} onModeChange={onThemeModeChange} />
          </div>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={handleSubmit}>
            <div className="space-y-2">
              <label className="text-sm font-medium" htmlFor="username">
                Username
              </label>
              <Input
                aria-describedby={error ? errorId : undefined}
                aria-invalid={error ? "true" : undefined}
                autoComplete="username"
                autoFocus
                disabled={isSubmitting}
                id="username"
                name="username"
                onChange={(event) => setUsername(event.target.value)}
                required
                value={username}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium" htmlFor="password">
                Password
              </label>
              <Input
                aria-describedby={error ? errorId : undefined}
                aria-invalid={error ? "true" : undefined}
                autoComplete="current-password"
                disabled={isSubmitting}
                id="password"
                name="password"
                onChange={(event) => setPassword(event.target.value)}
                required
                type="password"
                value={password}
              />
            </div>

            {error ? (
              <div
                className="flex items-center gap-2 rounded-md border border-destructive/40 px-3 py-2 text-sm text-destructive"
                id={errorId}
                role="alert"
              >
                <AlertCircle className="size-4 shrink-0" aria-hidden="true" />
                <span>{error}</span>
              </div>
            ) : null}

            <Button className="w-full" disabled={isSubmitting} type="submit">
              {isSubmitting ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : null}
              Sign in
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
