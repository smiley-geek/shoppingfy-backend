import React from "react";
import Head from "next/head";

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div>
      <Head>rick and morty</Head>
      <div> -- Layout --</div>
      <div>{children}</div>
    </div>
  );
}

export default Layout;
