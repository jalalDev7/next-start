import React, { ReactNode } from "react";

const layout = ({ children }: { children: ReactNode }) => {
  return (
    <div className="flex min-h-screen items-center justify-center bg-primary">
      <div className="flex flex-col bg-secondary rounded-xl p-4 m-4 w-full max-w-[500px] min-h-[500px] items-center justify-center">
        {children}
      </div>
    </div>
  );
};

export default layout;
