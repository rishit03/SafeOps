import { NextResponse, type NextRequest } from "next/server";

const protectedRoutes = [
  "/app",
  "/app/findings",
  "/app/attack-paths",
  "/app/remediation",
  "/app/assets",
  "/app/activity",
  "/app/audit",
  "/app/integrations",
  "/app/settings",
  "/app/planned",
];

export function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;

  const isProtectedRoute = protectedRoutes.some((route) => {
    return path === route || path.startsWith(`${route}/`);
  });

  const sessionCookie =
    request.cookies.get("authjs.session-token")?.value ||
    request.cookies.get("__Secure-authjs.session-token")?.value ||
    request.cookies.get("next-auth.session-token")?.value ||
    request.cookies.get("__Secure-next-auth.session-token")?.value;

  if (isProtectedRoute && !sessionCookie) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("callbackUrl", request.nextUrl.href);
    return NextResponse.redirect(loginUrl);
  }

  if (path === "/login" && sessionCookie) {
    return NextResponse.redirect(new URL("/app", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};