import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const isAdmin = Boolean(request.cookies.get('adminToken')?.value);

  const pathname = request.nextUrl.pathname;

  // ⚠️ Permitir acesso ao /admin (login), mas bloquear /admin/* se não for admin
  if (pathname.startsWith('/admin') && pathname !== '/admin') {
    if (!isAdmin) {
      return NextResponse.redirect(new URL('/admin', request.url));
    }
  }

  return NextResponse.next();
}

// Define quais rotas serão monitoradas
export const config = {
  matcher: ['/admin/:path*'],
};
