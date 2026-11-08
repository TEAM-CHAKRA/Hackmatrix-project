import { Link } from 'react-router-dom';
import { Compass } from 'lucide-react';
import { EmptyState } from '../components/ui/States.jsx';

export default function NotFoundPage() {
  return (
    <div className="mx-auto max-w-2xl px-4 py-20 sm:px-6">
      <EmptyState
        icon={Compass}
        title="Page not found"
        message="The page you are looking for does not exist."
        action={<Link to="/" className="btn-primary mt-2 text-xs">Back to Home</Link>}
      />
    </div>
  );
}
