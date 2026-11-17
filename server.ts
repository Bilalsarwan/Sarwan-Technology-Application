/**
 * Sarwan Technology Billing System
 * Local SQLite Express Server Entry Point (Web & Dev Runtime)
 *
 * Provides trusted local SQLite authentication, role-based access control,
 * transactional financial endpoints, Server-Sent Events (SSE) change push,
 * SQLite integrity/backup management, and Vite dev middleware.
 */

process.env.DISABLE_HMR = 'true';

process.on('uncaughtException', (err) => {
  console.error('Server process uncaught exception (handled):', err?.message || err);
});

process.on('unhandledRejection', (reason) => {
  console.warn('Server process unhandled rejection (handled):', reason);
});

import express, { Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  getDb,
  closeDb,
  runIntegrityCheck,
  createSqliteBackup,
  listSqliteBackups,
  restoreSqliteBackup,
  getBackupDir,
} from './src/db/sqlite';
import {
  getSetupStatusLocal,
  completeFirstRunSetupLocal,
  authenticateLocalUser,
  verifySuperAdminPasswordLocal,
  verifySessionLocal,
  authenticateCallerLocal,
  changePasswordLocal,
  revokeLocalSession,
} from './src/db/localAuthService';
import {
  dispatchLocalDbMethod,
  ensureRollingAutoBackup,
  addAuditLogLocal,
  correctPaymentLocal,
  advanceExpenseWorkflowLocal,
  saveInvoiceExpenseLocal,
  deleteInvoiceExpenseLocal,
  listExpensesLocal,
  updateBusinessSettingsLocal,
  createInvoiceWithAtomicNumberLocal,
  updateInvoiceLocal,
  getEligibleRemittanceRecipientsLocal,
  createProfitRemittanceRequestLocal,
  reviewProfitRemittanceRequestLocal,
  cancelApprovedRemittanceRequestLocal,
  recordProfitRemittanceReceiptLocal,
  saveInvoiceManagerTargetLocal,
  deleteAuditLogsLocal,
  deleteAllAuditLogsLocal,
  fetchAuditLogsPageLocal,
  getAuditDeletionLogsLocal,
} from './src/db/localDataService';
import { filterExpensesByScope } from './src/services/dashboardAuthorization';
import { Expense } from './src/types';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

function getCliArg(flag: string): string | undefined {
  for (let i = 0; i < process.argv.length; i++) {
    const arg = process.argv[i];
    if (arg === flag && process.argv[i + 1]) {
      return process.argv[i + 1];
    }
    if (arg.startsWith(`${flag}=`)) {
      return arg.slice(flag.length + 1);
    }
  }
  return undefined;
}

const defaultPort = process.env.PORT && process.env.PORT !== '8080' ? process.env.PORT : '3000';
const PORT = parseInt(getCliArg('--port') || process.env.APP_PORT || defaultPort, 10);
const HOST = getCliArg('--host') || process.env.HOST || '0.0.0.0';
const isProd = process.env.NODE_ENV === 'production';

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use((req, _res, next) => {
  if (req.path.startsWith('/api/') && req.path !== '/api/local-db/events') {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path}`);
  }
  next();
});

// ============================================================================
// SERVER-SENT EVENTS (SSE) FOR REAL-TIME SQLITE TOPIC UPDATES
// ============================================================================

const sseClients = new Set<Response>();

function broadcastTopics(topics: string[]): void {
  if (!topics || topics.length === 0 || sseClients.size === 0) return;
  const payload = JSON.stringify({ topics, timestamp: Date.now() });
  const frame = `event: db_change\ndata: ${payload}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(frame);
    } catch {
      sseClients.delete(client);
    }
  }
}

const METHOD_TOPICS: Record<string, string[]> = {
  updateBusinessSettings: ['settings'],
  saveReceiptDesignSettings: ['settings'],
  addAuditLog: ['auditLogs'],
  deleteAuditLogs: ['auditLogs'],
  deleteAllAuditLogs: ['auditLogs'],
  saveCustomer: ['customers'],
  setCustomerStatus: ['customers'],
  deleteCustomerSafely: ['customers'],
  unlinkCustomerUserAccount: ['customers'],
  migrateCustomerIdsInPlace: ['customers'],
  createInvoiceWithAtomicNumber: ['invoices', 'payments', 'customers', 'notifications', 'settings'],
  updateInvoice: ['invoices', 'payments', 'customers', 'notifications'],
  voidInvoice: ['invoices', 'payments', 'customers', 'notifications'],
  toggleInvoiceLock: ['invoices'],
  updateInvoiceBillingState: ['invoices', 'notifications'],
  deleteInvoicePermanently: ['invoices', 'payments', 'expenses', 'notifications'],
  cleanupVoidInvoiceSafe: ['invoices', 'payments', 'expenses', 'notifications'],
  addCashPayment: ['payments', 'invoices', 'customers', 'notifications'],
  correctPayment: ['payments', 'invoices', 'customers', 'notifications'],
  saveExpense: ['expenses', 'notifications'],
  advanceExpenseWorkflow: ['expenses', 'notifications'],
  saveInvoiceExpense: ['expenses', 'notifications'],
  deleteInvoiceExpense: ['expenses'],
  migratePendingExpensesToApproved: ['expenses'],
  createApplicationUser: ['users'],
  resetUserPasswordByAdmin: ['users'],
  updateUserRoleAndPermissions: ['users'],
  setUserAccountStatus: ['users'],
  deleteUserAccountSafely: ['users'],
  updateUserDiffOnly: ['users'],
  updateUserProfile: ['users'],
  saveEmployeeDocument: ['users'],
  deleteEmployeeDocument: ['users'],
  createNotification: ['notifications'],
  markNotificationAsRead: ['notifications'],
  markAllNotificationsAsRead: ['notifications'],
  deleteNotification: ['notifications'],
  createProfitRemittanceRequest: ['remittanceRequests', 'notifications'],
  reviewProfitRemittanceRequest: ['remittanceRequests', 'notifications'],
  cancelApprovedRemittanceRequest: ['remittanceRequests', 'notifications'],
  recordProfitRemittanceReceipt: ['remittanceRequests', 'remittanceReceipts', 'invoices', 'notifications'],
  saveInvoiceManagerTarget: ['invoiceManagerTargets', 'notifications'],
  saveService: ['services'],
  deleteService: ['services'],
  savePost: ['posts'],
  deletePost: ['posts'],
  saveProject: ['projects'],
  deleteProject: ['projects'],
  'backup:restore': ['*'],
};

const SUPER_ADMIN_ONLY_METHODS = new Set<string>([
  'createApplicationUser',
  'resetUserPasswordByAdmin',
  'updateUserRoleAndPermissions',
  'setUserAccountStatus',
  'deleteUserAccountSafely',
  'checkUserDeletionSafety',
  'getUsersCountMetrics',
  'deleteAuditLogs',
  'deleteAllAuditLogs',
  'fetchAuditLogsPage',
  'getAuditDeletionLogs',
  'updateBusinessSettings',
  'saveReceiptDesignSettings',
  'correctPayment',
  'voidInvoice',
  'toggleInvoiceLock',
  'deleteInvoicePermanently',
  'cleanupVoidInvoiceSafe',
  'traceVoidInvoiceDependencies',
  'reviewProfitRemittanceRequest',
  'cancelApprovedRemittanceRequest',
  'recordProfitRemittanceReceipt',
  'saveInvoiceManagerTarget',
  'exportFullBackupData',
  'backup:create',
  'backup:list',
  'backup:restore',
]);

app.get('/api/local-db/events', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  res.write(`event: connected\ndata: ${JSON.stringify({ ok: true })}\n\n`);
  sseClients.add(res);

  const keepAlive = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch {
      clearInterval(keepAlive);
      sseClients.delete(res);
    }
  }, 25000);

  req.on('close', () => {
    clearInterval(keepAlive);
    sseClients.delete(res);
  });
});

// Health & SQLite status endpoint
app.get('/api/health', (_req: Request, res: Response) => {
  let dbOk = false;
  try {
    const check = runIntegrityCheck();
    dbOk = check.ok;
  } catch {
    dbOk = false;
  }
  res.json({
    status: dbOk ? 'ok' : 'degraded',
    storage: 'sqlite',
    integrityOk: dbOk,
    system: 'Sarwan Technology Billing System',
    timestamp: new Date().toISOString(),
    environment: isProd ? 'production' : 'development',
  });
});

// Unified authenticated RPC bridge for Web runtime
app.post('/api/local-db/invoke', async (req: Request, res: Response) => {
  try {
    const { method, payload } = req.body || {};
    if (!method || typeof method !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Method name is required.',
      });
    }

    // Only read-only settings bootstrap may be called unauthenticated (LoginView branding)
    if (method !== 'getSettings') {
      const authCaller = await authenticateCallerLocal(req);
      if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
        return res.status(401).json({
          success: false,
          error: authCaller.error || 'Authentication required: Invalid or missing session token.',
        });
      }

      if (authCaller.userRole !== 'super_admin') {
        return res.status(403).json({
          success: false,
          error: `Access Denied: Only active Super Admin accounts are authorized to execute "${method}".`,
        });
      }
    }

    const result = await dispatchLocalDbMethod(method, payload || {});
    const topics = METHOD_TOPICS[method];
    if (topics) {
      broadcastTopics(topics);
    }

    return res.json({ success: true, result });
  } catch (err: any) {
    const message = err?.message || 'Local database operation failed.';
    const isPermission = message.includes('Access Denied') || message.includes('Unauthorized');
    return res.status(isPermission ? 403 : 400).json({
      success: false,
      error: message,
    });
  }
});

// ============================================================================
// AUTHENTICATION ENDPOINTS (LOCAL SQLITE + SCRYPT)
// ============================================================================

app.get('/api/auth/setup-status', (_req: Request, res: Response) => {
  try {
    return res.json(getSetupStatusLocal());
  } catch (err: any) {
    return res.status(500).json({
      needsSetup: false,
      error: err?.message || 'Failed to inspect administrator setup status.',
    });
  }
});

app.post('/api/auth/setup', async (req: Request, res: Response) => {
  try {
    const result = await completeFirstRunSetupLocal(req.body || {});
    broadcastTopics(['users', 'settings']);
    return res.json(result);
  } catch (err: any) {
    return res.status(400).json({
      success: false,
      error: err?.message || 'Initial Super Admin setup failed.',
    });
  }
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        error: 'Identifier and password are required.',
      });
    }

    const result = await authenticateLocalUser({ identifier, password });
    return res.json(result);
  } catch (err: any) {
    const errorMessage = err?.message || 'Authentication failed.';
    const statusCode =
      errorMessage.includes('Invalid username') || errorMessage.includes('Invalid password')
        ? 401
        : 400;

    return res.status(statusCode).json({
      success: false,
      error: errorMessage,
    });
  }
});

app.post('/api/auth/logout', async (req: Request, res: Response) => {
  try {
    const authHeader = (req.headers.authorization || req.headers.Authorization || '') as string;
    const tokenFromHeader = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : authHeader.trim();
    const token =
      tokenFromHeader ||
      (req.headers['x-session-token'] as string) ||
      (req.body?.idToken as string) ||
      '';
    if (token) {
      revokeLocalSession(token);
    }
    return res.json({ success: true });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: err?.message || 'Logout failed.',
    });
  }
});

app.post('/api/auth/change-password', async (req: Request, res: Response) => {
  try {
    const authHeader = (req.headers.authorization || req.headers.Authorization || '') as string;
    const tokenFromHeader = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : authHeader.trim();
    const idToken = tokenFromHeader || (req.body?.idToken as string) || '';
    const { newPassword, userId } = req.body || {};

    if (!newPassword) {
      return res.status(400).json({
        success: false,
        error: 'New password is required.',
      });
    }

    if (!idToken && !userId) {
      return res.status(401).json({
        success: false,
        error: 'Authentication session token is required.',
      });
    }

    const result = await changePasswordLocal({
      idToken,
      userId,
      newPassword,
    });

    if (!result.success) {
      const statusCode = result.error?.includes('session has expired') ? 401 : 400;
      return res.status(statusCode).json(result);
    }

    broadcastTopics(['users']);
    return res.json(result);
  } catch {
    return res.status(500).json({
      success: false,
      error: 'An unexpected error occurred while updating your password. Please try again.',
    });
  }
});

app.post('/api/auth/verify-super-admin', async (req: Request, res: Response) => {
  try {
    const { userId, password } = req.body || {};
    if (!userId || !password) {
      return res.status(400).json({
        isValid: false,
        error: 'User ID and password are required.',
      });
    }

    const result = await verifySuperAdminPasswordLocal({ userId, password });
    return res.json(result);
  } catch (err: any) {
    return res.status(500).json({
      isValid: false,
      error: err?.message || 'Verification failed.',
    });
  }
});

app.post('/api/auth/reversal-auth', async (req: Request, res: Response) => {
  try {
    const { userId, password, userRole } = req.body || {};
    if (userRole !== 'super_admin') {
      return res.status(403).json({
        isAuthorized: false,
        error: 'Access Denied: Only Super Admin is authorized to reverse payments.',
      });
    }

    const result = await verifySuperAdminPasswordLocal({ userId, password });
    if (!result.isValid) {
      return res.status(401).json({
        isAuthorized: false,
        error: result.error || 'Authentication Failed: Incorrect Super Admin password.',
      });
    }

    return res.json({ isAuthorized: true });
  } catch (err: any) {
    return res.status(500).json({
      isAuthorized: false,
      error: err?.message || 'Authorization check failed.',
    });
  }
});

app.post('/api/auth/verify-session', async (req: Request, res: Response) => {
  try {
    const authHeader = (req.headers.authorization || req.headers.Authorization || '') as string;
    const tokenFromHeader = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : authHeader.trim();
    const idToken = (req.body?.idToken as string) || tokenFromHeader;
    const userId = req.body?.userId as string;

    if (!idToken || !userId) {
      return res.status(400).json({
        isValid: false,
        error: 'Token and User ID are required.',
      });
    }

    const result = await verifySessionLocal({ idToken, userId });
    const statusCode = result.isValid ? 200 : 401;
    return res.status(statusCode).json(result);
  } catch (err: any) {
    return res.status(500).json({
      isValid: false,
      error: err?.message || 'Session verification error.',
    });
  }
});

// ============================================================================
// PAYMENTS & REVERSAL
// ============================================================================

app.post('/api/payments/reverse', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can reverse payments.',
      });
    }

    const {
      paymentId,
      invoiceId,
      reason,
      password,
      correctedAmount,
      correctedNote,
    } = req.body || {};

    if (!paymentId || !invoiceId || !reason || !password) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameters for payment reversal.',
      });
    }

    const replacementPaymentId = await correctPaymentLocal({
      paymentId,
      invoiceId,
      reason,
      password,
      userId: authCaller.userId,
      userName: authCaller.userName || 'Super Admin',
      userRole: 'super_admin',
      correctedAmount,
      correctedNote,
    });

    broadcastTopics(['payments', 'invoices', 'customers', 'notifications']);

    return res.json({
      success: true,
      paymentId,
      replacementPaymentId,
      message: 'Payment reversed successfully.',
    });
  } catch (err: any) {
    return res.status(400).json({
      success: false,
      error: err?.message || 'Payment reversal failed.',
    });
  }
});

// ============================================================================
// OPERATING & INVOICE EXPENSES
// ============================================================================

app.post('/api/expenses/workflow', async (req: Request, res: Response) => {
  try {
    const auth = await authenticateCallerLocal(req);
    if (!auth.isValid || !auth.user || !auth.userId || !auth.userRole) {
      return res.status(401).json({
        success: false,
        error: auth.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    const verifiedUserId = auth.userId;
    const verifiedUserRole = auth.userRole;
    const verifiedUserName = auth.userName || 'Staff';
    const verifiedJobTitle = auth.user.jobTitle || req.body?.userJobTitle || '';
    const verifiedPhotoURL = auth.user.photoURL || req.body?.userPhotoURL || '';

    const {
      expenseId,
      action,
      reason,
      corrections,
      title,
      amount,
      date,
      category,
      note,
      disbursedAmount,
      disbursementMethod,
      disbursementReference,
      disbursementNote,
      executionDate,
    } = req.body || {};

    if (!expenseId || !action) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameters for expense workflow action.',
      });
    }

    if (verifiedUserRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin is authorized to manage operating expenses.',
      });
    }

    const expenses = listExpensesLocal({ allTime: true });
    const existing = expenses.find((ex) => ex.id === expenseId) as Expense | undefined;
    if (!existing) {
      return res.status(404).json({
        success: false,
        error: `Expense record "${expenseId}" not found.`,
      });
    }

    if (
      (action === 'manager_approve' || action === 'admin_approve') &&
      existing.requestedBy &&
      existing.requestedBy.toLowerCase() === verifiedUserId.toLowerCase()
    ) {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: You cannot approve your own expense request.',
      });
    }

    if (
      action === 'reject' &&
      existing.requestedBy &&
      existing.requestedBy.toLowerCase() === verifiedUserId.toLowerCase()
    ) {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: You cannot reject your own expense request.',
      });
    }

    if (action === 'manager_approve') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Legacy manager approval workflow has been discontinued.',
      });
      if (existing.status !== 'pending_manager') {
        return res.status(400).json({
          success: false,
          error:
            existing.status === 'pending_admin' || existing.status === 'approved' || existing.status === 'executed'
              ? 'This expense has already been approved or advanced past manager stage.'
              : `Expense cannot be approved at manager stage because current status is "${existing.status}".`,
        });
      }
    } else if (action === 'admin_approve') {
      if (verifiedUserRole !== 'super_admin') {
        return res.status(403).json({
          success: false,
          error: 'Access Denied: Only Super Admin can approve expenses at the admin stage.',
        });
      }
      if (existing.requestedByRole === 'payment_collector' && existing.status === 'pending_manager') {
        return res.status(403).json({
          success: false,
          error: 'Access Denied: Payment Collector expenses must first receive Invoice Manager approval before Super Admin approval.',
        });
      }
      if (existing.status !== 'pending_admin') {
        return res.status(400).json({
          success: false,
          error: `Expense cannot be approved at admin stage because current status is "${existing.status}".`,
        });
      }
    } else if (action === 'admin_execute') {
      if (verifiedUserRole !== 'super_admin') {
        return res.status(403).json({
          success: false,
          error: 'Access Denied: Only Super Admin can execute and disburse expenses.',
        });
      }
      if (existing.status === 'executed' || existing.executionStatus === 'executed') {
        return res.status(400).json({
          success: false,
          error: 'This expense has already been executed and disbursed.',
        });
      }
      if (existing.status !== 'approved') {
        return res.status(400).json({
          success: false,
          error: `Expense cannot be executed because current status is "${existing.status}". Only approved expenses can be executed.`,
        });
      }
      if (disbursedAmount !== undefined) {
        const numDisbursed = Number(disbursedAmount);
        if (!Number.isFinite(numDisbursed) || numDisbursed <= 0) {
          return res.status(400).json({
            success: false,
            error: 'Disbursed amount must be a positive number.',
          });
        }
        if (numDisbursed > existing.amount) {
          return res.status(400).json({
            success: false,
            error: `Disbursed amount (${numDisbursed} AFN) cannot exceed approved amount (${existing.amount} AFN).`,
          });
        }
      }
    } else if (action === 'reject') {
      if (verifiedUserRole !== 'super_admin') {
        return res.status(403).json({
          success: false,
          error: 'Access Denied: Only Super Admin can reject expenses.',
        });
      }
      if (existing.status !== 'pending_manager' && existing.status !== 'pending_admin') {
        return res.status(400).json({
          success: false,
          error: `Expense cannot be rejected because current status is "${existing.status}". Only pending expenses can be rejected.`,
        });
      }
      if (existing.status === 'pending_admin' && verifiedUserRole !== 'super_admin') {
        return res.status(403).json({
          success: false,
          error: 'Access Denied: Only Super Admin can reject expenses at the admin stage.',
        });
      }
      const reasonText = (reason || '').trim();
      if (!reasonText || reasonText.length < 3) {
        return res.status(400).json({
          success: false,
          error: 'A meaningful rejection reason (at least 3 characters) is required to reject an expense.',
        });
      }
    } else if (action === 'resubmit') {
      if (verifiedUserRole === 'super_admin') {
        return res.status(403).json({
          success: false,
          error: 'Access Denied: Super Admin cannot resubmit expense requests.',
        });
      }
      const isOwner =
        existing.requestedBy &&
        existing.requestedBy.toLowerCase() === verifiedUserId.toLowerCase();
      if (!isOwner) {
        return res.status(403).json({
          success: false,
          error: 'Access Denied: Only the original authorized requester can edit and resubmit their rejected expense request.',
        });
      }
      if (existing.status !== 'rejected') {
        return res.status(400).json({
          success: false,
          error: 'Only rejected expenses can be resubmitted.',
        });
      }
      const correctionsText = (corrections || reason || '').trim();
      if (!correctionsText || correctionsText.length < 3) {
        return res.status(400).json({
          success: false,
          error: 'A resubmission note explaining corrections (at least 3 characters) is required to resubmit a rejected expense.',
        });
      }
    } else {
      return res.status(400).json({
        success: false,
        error: `Invalid workflow action: "${action}".`,
      });
    }

    advanceExpenseWorkflowLocal({
      expenseId,
      action,
      userId: verifiedUserId,
      userName: verifiedUserName,
      userRole: verifiedUserRole,
      userJobTitle: verifiedJobTitle,
      userPhotoURL: verifiedPhotoURL,
      reason,
      corrections,
      title,
      amount,
      date,
      category,
      note,
      disbursedAmount: disbursedAmount !== undefined ? Number(disbursedAmount) : undefined,
      disbursementMethod,
      disbursementReference,
      disbursementNote,
      executionDate,
    });

    broadcastTopics(['expenses', 'notifications']);

    return res.json({
      success: true,
      message: `Expense workflow action "${action}" executed successfully.`,
    });
  } catch (err: any) {
    return res.status(400).json({
      success: false,
      error: err?.message || 'Expense workflow execution failed.',
    });
  }
});

app.post('/api/expenses/save', async (req: Request, res: Response) => {
  try {
    const auth = await authenticateCallerLocal(req);
    if (!auth.isValid || !auth.user || !auth.userId || !auth.userRole) {
      return res.status(401).json({
        success: false,
        error: auth.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    const {
      id,
      invoiceId,
      billNumber,
      title,
      amount,
      date,
      category,
      note,
    } = req.body || {};

    if (!invoiceId || !title || amount === undefined || !date) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameters for saving invoice expense.',
      });
    }

    const savedId = saveInvoiceExpenseLocal({
      id,
      invoiceId,
      billNumber,
      title,
      amount: Number(amount),
      date,
      category,
      note,
      userId: auth.userId,
      userName: auth.userName || 'Staff',
      userRole: auth.userRole,
      userJobTitle: auth.user.jobTitle || req.body?.userJobTitle || '',
      userPhotoURL: auth.user.photoURL || req.body?.userPhotoURL || '',
    });

    broadcastTopics(['expenses', 'notifications']);

    return res.json({
      success: true,
      id: savedId,
      message: 'Invoice expense saved successfully.',
    });
  } catch (err: any) {
    const msg = err?.message || 'Saving invoice expense failed.';
    return res.status(msg.includes('Access Denied') ? 403 : 400).json({
      success: false,
      error: msg,
    });
  }
});

app.post('/api/expenses/by-invoice', async (req: Request, res: Response) => {
  try {
    const auth = await authenticateCallerLocal(req);
    if (!auth.isValid || !auth.user || !auth.userId || !auth.userRole) {
      return res.status(401).json({
        success: false,
        error: auth.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    const { invoiceId } = req.body || {};
    if (!invoiceId) {
      return res.status(400).json({
        success: false,
        error: 'Missing required invoiceId parameter.',
      });
    }

    if (auth.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only active Super Admin accounts can view invoice expenses.',
      });
    }

    const all = listExpensesLocal({ invoiceId, allTime: true });
    const expenses = filterExpensesByScope(all, auth.userRole, auth.userId);
    return res.json({ success: true, expenses });
  } catch (err: any) {
    return res.status(400).json({
      success: false,
      error: err?.message || 'Failed to fetch invoice expenses.',
    });
  }
});

app.post('/api/expenses/delete', async (req: Request, res: Response) => {
  try {
    const auth = await authenticateCallerLocal(req);
    if (!auth.isValid || !auth.user || !auth.userId || !auth.userRole) {
      return res.status(401).json({
        success: false,
        error: auth.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    const { expenseId, invoiceId, billNumber } = req.body || {};
    if (!expenseId || !invoiceId) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameters for deleting invoice expense.',
      });
    }

    if (auth.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can delete invoice expenses.',
      });
    }

    deleteInvoiceExpenseLocal({
      expenseId,
      invoiceId,
      billNumber,
      userId: auth.userId,
      userName: auth.userName || 'Staff',
      userRole: auth.userRole,
    });

    broadcastTopics(['expenses']);

    return res.json({
      success: true,
      message: 'Invoice expense deleted successfully.',
    });
  } catch (err: any) {
    return res.status(400).json({
      success: false,
      error: err?.message || 'Deleting invoice expense failed.',
    });
  }
});

// ============================================================================
// BUSINESS SETTINGS
// ============================================================================

app.post('/api/settings/save', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin is authorized to update business settings.',
      });
    }

    const { settings: newSettings } = req.body || {};
    if (!newSettings || typeof newSettings !== 'object') {
      return res.status(400).json({
        success: false,
        error: 'Invalid settings payload provided.',
      });
    }

    if (newSettings.nextInvoiceNumber !== undefined) {
      const rawVal = newSettings.nextInvoiceNumber;
      const num = typeof rawVal === 'string' && rawVal.trim() === '' ? NaN : Number(rawVal);
      if (isNaN(num) || !Number.isInteger(num) || num <= 0) {
        return res.status(400).json({
          success: false,
          error: 'Invalid Next Invoice Number: Must be a valid positive integer greater than zero.',
        });
      }
      newSettings.nextInvoiceNumber = num;
    }

    if (newSettings.invoicePrefix !== undefined) {
      const trimmedPrefix = String(newSettings.invoicePrefix).trim();
      if (!trimmedPrefix) {
        return res.status(400).json({
          success: false,
          error: 'Invalid Invoice Prefix: Prefix cannot be empty.',
        });
      }
      newSettings.invoicePrefix = trimmedPrefix;
    }

    updateBusinessSettingsLocal(newSettings, authCaller.userId, authCaller.userName || 'Super Admin');
    broadcastTopics(['settings']);

    return res.json({
      success: true,
      message: 'Business settings saved successfully.',
    });
  } catch (err: any) {
    console.error('Server settings save error:', err);
    return res.status(500).json({
      success: false,
      error: err?.message || 'Failed to save settings on server.',
    });
  }
});

// ============================================================================
// INVOICES
// ============================================================================

app.post('/api/invoices/create', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can create invoices.',
      });
    }

    const {
      customerId,
      customerSnapshot,
      companySnapshot,
      date,
      items,
      totalAmount,
      note,
      initialCashPaid,
      paymentNote,
      requestId,
      templateId,
      billingState,
      assignedCollectorId,
      assignedCollectorName,
    } = req.body || {};

    if (!customerId || !customerSnapshot || !items || totalAmount === undefined || !date) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameters for invoice creation.',
      });
    }

    const created = createInvoiceWithAtomicNumberLocal({
      customerId,
      customerSnapshot,
      companySnapshot,
      date,
      items,
      totalAmount,
      note: note || '',
      initialCashPaid,
      paymentNote,
      requestId,
      userId: authCaller.userId,
      userName: authCaller.userName,
      assignedCollectorId,
      assignedCollectorName,
      templateId,
      billingState: billingState || 'quotation',
    });

    broadcastTopics(['invoices', 'payments', 'customers', 'notifications', 'settings']);
    return res.json({ success: true, invoice: created });
  } catch (err: any) {
    console.error('Server error creating invoice:', err);
    const isValidationErr =
      err?.message?.includes('Cannot create invoice') ||
      err?.message?.includes('cannot exceed') ||
      err?.message?.includes('Inactive') ||
      err?.message?.includes('Blocked') ||
      err?.message?.includes('already exists') ||
      err?.message?.includes('duplicate');
    return res.status(isValidationErr ? 400 : 500).json({
      success: false,
      error: err?.message || 'Failed to create invoice on the server.',
    });
  }
});

app.post('/api/invoices/update', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can edit invoices.',
      });
    }

    const { invoiceId, params, existingPaymentsTotal, previousInvoice } = req.body || {};

    if (!invoiceId || !params) {
      return res.status(400).json({
        success: false,
        error: 'Invoice ID and update parameters are required.',
      });
    }

    updateInvoiceLocal(
      invoiceId,
      params,
      Number(existingPaymentsTotal) || 0,
      authCaller.userId,
      authCaller.userName,
      previousInvoice
    );

    broadcastTopics(['invoices', 'payments', 'customers', 'notifications']);
    return res.json({ success: true });
  } catch (err: any) {
    console.error('Server error updating invoice:', err);
    const isValidationErr =
      err?.message?.includes('locked') ||
      err?.message?.includes('not found') ||
      err?.message?.includes('void') ||
      err?.message?.includes('rejected');
    return res.status(isValidationErr ? 400 : 500).json({
      success: false,
      error: err?.message || 'Failed to update invoice on the server.',
    });
  }
});

// ============================================================================
// PROFIT REMITTANCE ENDPOINTS
// ============================================================================

app.get('/api/profit-remittance/recipients', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can view remittance recipients.',
      });
    }

    const recipients = getEligibleRemittanceRecipientsLocal().map((u) => ({
      id: u.id,
      userId: u.userId || u.id,
      username: u.username || '',
      name: u.name || u.username || 'Staff User',
      role: u.role,
      jobTitle: u.jobTitle || 'Super Administrator',
      photoURL: u.photoURL || '',
      email: u.email || '',
      status: 'active',
    }));

    return res.json({ success: true, recipients });
  } catch (err: any) {
    console.error('Server error fetching remittance recipients:', err);
    return res.status(500).json({
      success: false,
      error: err?.message || 'Failed to fetch remittance recipients.',
    });
  }
});

app.post('/api/profit-remittance/request', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can request profit remittance.',
      });
    }

    const {
      invoiceId,
      requestedAmount,
      note,
      recipientId,
      recipientName,
      recipientRole,
      recipientJobTitle,
      recipientPhotoURL,
    } = req.body || {};

    if (!invoiceId || requestedAmount === undefined) {
      return res.status(400).json({
        success: false,
        error: 'Invoice ID and requested amount are required.',
      });
    }

    if (!recipientId || !recipientName || !recipientRole) {
      return res.status(400).json({
        success: false,
        error: 'A valid recipient (Request To / Pay To) must be selected.',
      });
    }

    if (recipientRole !== 'super_admin') {
      return res.status(400).json({
        success: false,
        error: 'Recipient must be an active Super Admin.',
      });
    }

    const request = createProfitRemittanceRequestLocal({
      invoiceId,
      requestedAmount: Number(requestedAmount),
      note,
      managerId: authCaller.userId,
      managerName: authCaller.userName || 'Super Admin',
      managerRole: authCaller.userRole,
      managerJobTitle: authCaller.user?.jobTitle,
      managerPhotoURL: authCaller.user?.photoURL,
      recipientId,
      recipientName,
      recipientRole,
      recipientJobTitle,
      recipientPhotoURL,
    });

    broadcastTopics(['remittanceRequests', 'notifications']);
    return res.json({ success: true, request });
  } catch (err: any) {
    console.error('Server error creating remittance request:', err);
    return res.status(400).json({
      success: false,
      error: err?.message || 'Failed to create profit remittance request.',
    });
  }
});

app.post('/api/profit-remittance/review', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can approve or reject profit remittance requests.',
      });
    }

    const { requestId, action, reviewNote } = req.body || {};
    if (!requestId || !action || (action !== 'approve' && action !== 'reject')) {
      return res.status(400).json({
        success: false,
        error: 'Request ID and valid action ("approve" | "reject") are required.',
      });
    }

    reviewProfitRemittanceRequestLocal({
      requestId,
      action,
      reviewNote,
      reviewerId: authCaller.userId,
      reviewerName: authCaller.userName || 'Super Admin',
      reviewerRole: authCaller.userRole,
    });

    broadcastTopics(['remittanceRequests', 'notifications']);
    return res.json({ success: true, message: `Remittance request ${action}d successfully.` });
  } catch (err: any) {
    console.error('Server error reviewing remittance request:', err);
    return res.status(400).json({
      success: false,
      error: err?.message || 'Failed to review profit remittance request.',
    });
  }
});

app.post('/api/profit-remittance/cancel', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can cancel profit remittance requests.',
      });
    }

    const { requestId, cancelReason } = req.body || {};
    if (!requestId) {
      return res.status(400).json({
        success: false,
        error: 'Request ID is required.',
      });
    }

    cancelApprovedRemittanceRequestLocal({
      requestId,
      cancelReason,
      reviewerId: authCaller.userId,
      reviewerName: authCaller.userName || 'Super Admin',
      reviewerRole: authCaller.userRole,
    });

    broadcastTopics(['remittanceRequests', 'notifications']);
    return res.json({ success: true, message: 'Remittance request cancelled successfully.' });
  } catch (err: any) {
    console.error('Server error cancelling remittance request:', err);
    return res.status(400).json({
      success: false,
      error: err?.message || 'Failed to cancel profit remittance request.',
    });
  }
});

app.post('/api/profit-remittance/receipt', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can record actual receipt of profit remittance.',
      });
    }

    const { requestId, actualAmount, referenceNumber, note } = req.body || {};
    if (!requestId || actualAmount === undefined) {
      return res.status(400).json({
        success: false,
        error: 'Request ID and actual amount are required.',
      });
    }

    const receipt = recordProfitRemittanceReceiptLocal({
      requestId,
      actualAmount: Number(actualAmount),
      referenceNumber,
      note,
      adminId: authCaller.userId,
      adminName: authCaller.userName || 'Super Admin',
      adminRole: authCaller.userRole,
    });

    broadcastTopics(['remittanceRequests', 'remittanceReceipts', 'invoices', 'notifications']);
    return res.json({ success: true, receipt });
  } catch (err: any) {
    console.error('Server error recording remittance receipt:', err);
    return res.status(400).json({
      success: false,
      error: err?.message || 'Failed to record profit remittance receipt.',
    });
  }
});

// ============================================================================
// MONTHLY TARGETS
// ============================================================================

app.post('/api/targets/save', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can assign or edit monthly targets.',
      });
    }

    const { managerId, managerName, managerEmail, month, targetAmount, note } = req.body || {};

    const target = saveInvoiceManagerTargetLocal({
      managerId,
      managerName: managerName || 'Super Admin',
      managerEmail,
      month,
      targetAmount,
      note,
      adminId: authCaller.userId,
      adminName: authCaller.userName || 'Super Admin',
      adminRole: 'super_admin',
    });

    broadcastTopics(['invoiceManagerTargets', 'notifications']);
    return res.json({ success: true, target });
  } catch (err: any) {
    console.error('Server error saving monthly target:', err);
    return res.status(400).json({
      success: false,
      error: err?.message || 'Failed to save monthly target.',
    });
  }
});

// ============================================================================
// AUDIT LOGS MANAGEMENT
// ============================================================================

app.post('/api/audit-logs/delete', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin is authorized to delete audit records.',
      });
    }

    const { logId, logIds } = req.body || {};
    const result = deleteAuditLogsLocal({
      logId,
      logIds,
      adminId: authCaller.userId,
      adminName: authCaller.userName || 'Super Admin',
      adminRole: authCaller.userRole,
    });

    broadcastTopics(['auditLogs']);
    return res.json(result);
  } catch (err: any) {
    console.error('Audit log deletion error:', err);
    return res.status(400).json({
      success: false,
      error: err?.message || 'Failed to process audit log deletion.',
    });
  }
});

app.post('/api/audit-logs/delete-all', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required: Invalid or missing session token.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin is authorized to purge audit records.',
      });
    }

    const { confirmationText } = req.body || {};
    const result = deleteAllAuditLogsLocal({
      confirmationText,
      adminId: authCaller.userId,
      adminName: authCaller.userName || 'Super Admin',
      adminRole: authCaller.userRole,
    });

    broadcastTopics(['auditLogs']);
    return res.json(result);
  } catch (err: any) {
    console.error('Delete all audit logs notice:', err?.message);
    return res.status(400).json({
      success: false,
      error: err?.message || 'Failed to delete all audit logs.',
    });
  }
});

app.post('/api/audit-logs/page', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can view audit logs.',
      });
    }

    const result = fetchAuditLogsPageLocal(req.body || {});
    return res.json(result);
  } catch (err: any) {
    console.error('Audit logs pagination fetch error:', err);
    return res.status(500).json({
      success: false,
      error: err?.message || 'Failed to fetch paginated audit logs.',
    });
  }
});

app.get('/api/audit-logs/deletion-history', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.user || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({
        success: false,
        error: authCaller.error || 'Authentication required.',
      });
    }

    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Access Denied: Only Super Admin can view deletion audit records.',
      });
    }

    const records = getAuditDeletionLogsLocal(50);
    return res.json({
      success: true,
      records,
      count: records.length,
    });
  } catch (err: any) {
    console.error('Audit deletion logs fetch error:', err);
    return res.status(500).json({
      success: false,
      error: err?.message || 'Failed to fetch audit deletion logs.',
    });
  }
});

// ============================================================================
// LOCAL SQLITE BACKUP, INTEGRITY & RESTORE ENDPOINTS
// ============================================================================

app.get('/api/backup/integrity', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }
    const integrity = runIntegrityCheck();
    return res.json({ success: true, ...integrity });
  } catch (err: any) {
    return res.status(500).json({ success: false, ok: false, error: err?.message || 'Integrity check failed.' });
  }
});

app.get('/api/backup/list', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.userRole) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }
    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({ success: false, error: 'Access Denied: Super Admin only.' });
    }
    return res.json({
      success: true,
      backupDir: getBackupDir(),
      backups: listSqliteBackups(),
      integrity: runIntegrityCheck(),
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err?.message || 'Failed to list backups.' });
  }
});

app.post('/api/backup/create', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }
    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({ success: false, error: 'Access Denied: Super Admin only.' });
    }

    const created = await createSqliteBackup();
    addAuditLogLocal({
      action: 'update_settings',
      userId: authCaller.userId,
      userName: authCaller.userName || 'Super Admin',
      userRole: authCaller.userRole,
      entityType: 'security',
      entityId: path.basename(created.backupPath),
      summary: `Created verified SQLite database backup "${path.basename(created.backupPath)}" (${(created.sizeBytes / 1024).toFixed(1)} KB).`,
    });

    return res.json({
      ...created,
      fileName: path.basename(created.backupPath),
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err?.message || 'Failed to create SQLite backup.' });
  }
});

app.post('/api/backup/restore', async (req: Request, res: Response) => {
  try {
    const authCaller = await authenticateCallerLocal(req);
    if (!authCaller.isValid || !authCaller.userId || !authCaller.userRole) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }
    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({ success: false, error: 'Access Denied: Super Admin only.' });
    }

    const { fileName, backupBase64 } = req.body || {};
    let sourcePath = '';

    if (backupBase64 && typeof backupBase64 === 'string') {
      const base64Clean = backupBase64.includes(',') ? backupBase64.split(',').pop() || '' : backupBase64;
      const buf = Buffer.from(base64Clean, 'base64');
      if (buf.length < 1024) {
        return res.status(400).json({ success: false, error: 'Uploaded SQLite backup file is empty or invalid.' });
      }
      const uploadsDir = path.join(getBackupDir(), 'uploads');
      fs.mkdirSync(uploadsDir, { recursive: true });
      const safeName = path.basename(String(fileName || `restore_${Date.now()}.sqlite`));
      sourcePath = path.join(uploadsDir, `${Date.now()}_${safeName}`);
      fs.writeFileSync(sourcePath, buf);
    } else if (fileName && typeof fileName === 'string') {
      const safeName = path.basename(fileName);
      sourcePath = path.join(getBackupDir(), safeName);
    } else {
      return res.status(400).json({
        success: false,
        error: 'Please select an existing backup or upload a .sqlite database file to restore.',
      });
    }

    const restored = await restoreSqliteBackup(sourcePath);
    addAuditLogLocal({
      action: 'update_settings',
      userId: authCaller.userId,
      userName: authCaller.userName || 'Super Admin',
      userRole: authCaller.userRole,
      entityType: 'security',
      entityId: path.basename(sourcePath),
      summary: `Restored SQLite database from backup "${path.basename(sourcePath)}". Pre-restore safety snapshot saved.`,
    });

    broadcastTopics(['*']);
    return res.json(restored);
  } catch (err: any) {
    return res.status(400).json({
      success: false,
      error: err?.message || 'SQLite database restore failed.',
    });
  }
});

app.get('/api/backup/download/:fileName', async (req: Request, res: Response) => {
  try {
    const tokenQuery = typeof req.query.token === 'string' ? req.query.token : '';
    const authCaller = await authenticateCallerLocal({
      headers: {
        ...req.headers,
        ...(tokenQuery && !req.headers.authorization ? { authorization: `Bearer ${tokenQuery}` } : {}),
      },
      body: req.body,
    });
    if (!authCaller.isValid || !authCaller.userRole) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }
    if (authCaller.userRole !== 'super_admin') {
      return res.status(403).json({ success: false, error: 'Access Denied: Super Admin only.' });
    }

    const safeName = path.basename(String(req.params.fileName || ''));
    const fullPath = path.join(getBackupDir(), safeName);
    if (!safeName || !fs.existsSync(fullPath)) {
      return res.status(404).json({ success: false, error: 'Backup file not found.' });
    }

    return res.download(fullPath, safeName);
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err?.message || 'Failed to download backup.' });
  }
});

app.use((err: any, req: Request, res: Response, next: any) => {
  if (err) {
    if (err.status === 413 || err.type === 'entity.too.large') {
      return res.status(413).json({
        success: false,
        error: 'Payload Too Large: The uploaded data or image exceeds maximum permitted size. Please choose an image under 5MB.',
      });
    }
    if (req.path.startsWith('/api/')) {
      return res.status(err.status || 500).json({
        success: false,
        error: err.message || 'Internal Server Error',
      });
    }
  }
  next(err);
});

// Initialize Frontend Handling (Vite in Dev, Static in Prod)
async function startServer() {
  try {
    getDb();
  } catch (initErr) {
    console.error('SQLite bootstrap warning:', initErr);
  }

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
        ws: false,
        watch: null,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  const server = app.listen(PORT, HOST, () => {
    console.log(`Sarwan Billing System (SQLite Local) running on http://${HOST}:${PORT}`);
  });

  server.on('error', (err: any) => {
    if (err?.code === 'EADDRINUSE') {
      console.error(`Port ${PORT} is currently in use.`, err);
    } else {
      console.error('HTTP server event error:', err);
    }
  });

  setTimeout(() => {
    ensureRollingAutoBackup(7).catch((err) => {
      console.warn('Rolling auto-backup notice:', err);
    });
  }, 300);

  const handleShutdown = () => {
    server.close(() => {
      closeDb();
      process.exit(0);
    });
  };
  process.on('SIGTERM', handleShutdown);
  process.on('SIGINT', handleShutdown);
}

startServer().catch((err) => {
  console.error('Server startup error:', err);
});
