import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import { Route, Switch, Router as WouterRouter } from 'wouter';
import { JobStateProvider } from './contexts/JobStateContext';
import { OverviewPage } from './pages/OverviewPage';
import { ScanPage } from './pages/ScanPage';
import { FindingsPage } from './pages/FindingsPage';
import { EvidencePage } from './pages/EvidencePage';
import { ReasoningPage } from './pages/ReasoningPage';
import { ReportsPage } from './pages/ReportsPage';
import { JobsPage } from './pages/JobsPage';
import { TerminalPage } from './pages/TerminalPage';
import { HealthPage } from './pages/HealthPage';
import { DynamicPage } from './pages/DynamicPage';

const queryClient = new QueryClient();

function Router() {
  return (
    <Switch>
      <Route path="/" component={OverviewPage} />
      <Route path="/scan" component={ScanPage} />
      <Route path="/findings" component={FindingsPage} />
      <Route path="/evidence" component={EvidencePage} />
      <Route path="/reasoning" component={ReasoningPage} />
      <Route path="/reports" component={ReportsPage} />
      <Route path="/jobs" component={JobsPage} />
      <Route path="/dynamic" component={DynamicPage} />
      <Route path="/terminal" component={TerminalPage} />
      <Route path="/health" component={HealthPage} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <JobStateProvider>
          <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
            <Router />
          </WouterRouter>
          <Toaster />
        </JobStateProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
