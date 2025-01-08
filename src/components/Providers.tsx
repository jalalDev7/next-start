"use client";
import type { Session } from "next-auth";
import { SessionProvider } from "next-auth/react";
import React, { ReactNode, useState } from "react";
import { QueryClient, QueryClientProvider } from "react-query";

const Providers = ({
  children,
  session,
}: {
  children: ReactNode;
  session: Session | null;
}) => {
  const [queryClient] = useState(() => new QueryClient());
  return (
    <SessionProvider session={session}>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </SessionProvider>
  );
};

export default Providers;
