import HeroSection from '../components/HeroSection.jsx';
import PlatformIntro from '../components/PlatformIntro.jsx';
import WorkflowTimeline from '../components/WorkflowTimeline.jsx';
import IntelligenceSection from '../components/IntelligenceSection.jsx';
import BlockchainVisualization from '../components/BlockchainVisualization.jsx';
import FinalCTA from '../components/FinalCTA.jsx';

/**
 * Home — the CYBERLENS landing page. About and mission live here
 * (there is intentionally no separate About route).
 *
 * Section rhythm: globe hero → midnight → circuit band → midnight → midnight
 * → lens-ring CTA.
 */
export default function HomePage() {
  return (
    <>
      <HeroSection />
      <PlatformIntro />
      <WorkflowTimeline />
      <IntelligenceSection />
      <BlockchainVisualization />
      <FinalCTA />
    </>
  );
}
