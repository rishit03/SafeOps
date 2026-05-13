import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

export const authOptions: NextAuthOptions = {
  pages: {
    signIn: "/login",
  },

  session: {
    strategy: "jwt",
  },

  secret: process.env.NEXTAUTH_SECRET,

  providers: [
    CredentialsProvider({
      name: "SafeOps Admin",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },

      async authorize(credentials) {
        const email = String(credentials?.email || "");
        const password = String(credentials?.password || "");

        const adminEmail = process.env.SAFEOPS_ADMIN_EMAIL;
        const adminPassword = process.env.SAFEOPS_ADMIN_PASSWORD;

        if (email === adminEmail && password === adminPassword) {
          return {
            id: "safeops-admin",
            email,
            name: "SafeOps Admin",
          };
        }

        return null;
      },
    }),
  ],
};