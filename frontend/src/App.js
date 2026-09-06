import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Toaster } from "@/components/ui/sonner";
import LandingPage from "@/pages/LandingPage";
import ScanPage from "@/pages/ScanPage";
import ResultsPage from "@/pages/ResultsPage";
import IncidentPage from "@/pages/IncidentPage";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/scan/:scanId" element={<ScanPage />} />
        <Route path="/results/:scanId" element={<ResultsPage />} />
        <Route path="/incident" element={<IncidentPage />} />
      </Routes>
      <Toaster theme="dark" position="bottom-right" />
    </BrowserRouter>
  );
}

export default App;
