import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { jwtVerify } from "jose";

// Define protected routes
const protectedRoutes = ["/dashboard", "/menu", "/orders", "/profile"];

// Define public routes
const publicRoutes = ["/signin", "/signup", "/api/signin", "/api/signup"];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // ✅ Allow static files & Next internals
  if (
    pathname.startsWith("/_next/") ||
    pathname.startsWith("/favicon.ico") ||
    pathname.includes(".")
  ) {
    return NextResponse.next();
  }

  // ✅ Allow public routes
  if (publicRoutes.includes(pathname)) {
    return NextResponse.next();
  }

  // ✅ Allow most API routes except protected ones
  if (
    pathname.startsWith("/api/") &&
    !pathname.startsWith("/api/protected/")
  ) {
    return NextResponse.next();
  }

  // ✅ Check if route is protected (FIXED)
  const isProtectedRoute = protectedRoutes.some((route) =>
    pathname.startsWith(route)
  );

  // ✅ Get token from cookies or Authorization header
  let token = request.cookies.get("token")?.value;

  if (!token) {
    const authHeader = request.headers.get("authorization");
    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.substring(7);
    }
  }

  // 🔍 Debug logs (remove in production)
  console.log("PATH:", pathname);
  console.log("TOKEN:", token);

  // ❌ If no token & accessing protected route → redirect
  if (!token && isProtectedRoute) {
    const signinUrl = new URL("/signin", request.url);
    signinUrl.searchParams.set("redirect", pathname);
    return NextResponse.redirect(signinUrl);
  }

  // ✅ If token exists → verify
  if (token) {
    try {
      const secret = new TextEncoder().encode(process.env.JWT_SECRET);
      await jwtVerify(token, secret);

      // 🚫 Prevent logged-in users from accessing auth pages
      if (pathname === "/signin" || pathname === "/signup") {
        return NextResponse.redirect(new URL("/", request.url));
      }

      return NextResponse.next();
    } catch (err) {
      console.log("JWT ERROR:", err);

      // ❌ Invalid token → clear cookie & redirect
      const response = NextResponse.redirect(
        new URL("/signin", request.url)
      );
      response.cookies.delete("token");
      return response;
    }
  }

  return NextResponse.next();
}

// ✅ Matcher config
export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
