import React from 'react';
import { AuthProvider } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import { RoleRouter } from './components/RoleRouter';
import { ToastContainer, NotificationTrayDrawer } from './components/ToastContainer';

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <RoleRouter />
        <ToastContainer />
        <NotificationTrayDrawer />
      </AuthProvider>
    </ToastProvider>
  );
}
