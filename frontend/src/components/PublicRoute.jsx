import React from 'react';
import { Navigate, Outlet, useSearchParams } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.js';
import { LoadingSpinner } from './LoadingSpinner.jsx';

export const PublicRoute = () => {
  const { isAuthenticated, isLoading } = useAuth();
  const [searchParams] = useSearchParams();

  if (isLoading) {
    return (
      <div className="min-h-[70vh] flex items-center justify-center">
        <LoadingSpinner text="Checking session..." />
      </div>
    );
  }

  const extId = searchParams.get('extId');
  const extState = searchParams.get('state');
  const isExtensionAuthFlow = Boolean(extId && extState);

  // If user is already authenticated and this is NOT an extension authorization flow, redirect to /scanner
  if (isAuthenticated && !isExtensionAuthFlow) {
    return <Navigate to="/scanner" replace />;
  }

  return <Outlet />;
};
