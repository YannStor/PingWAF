export function requiredEnv(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) {
    throw new Error(
      `${name} must be set explicitly; E2E never falls back to a shared demo or a real domain`,
    )
  }
  return value
}
