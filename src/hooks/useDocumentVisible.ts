import { useEffect, useState } from 'react';

/** True while the window/tab is visible. Used to gate polling. */
export function useDocumentVisible(): boolean {
  const [visible, setVisible] = useState<boolean>(() =>
    typeof document === 'undefined' ? true : document.visibilityState === 'visible',
  );

  useEffect(() => {
    const onChange = () => {
      setVisible(document.visibilityState === 'visible');
    };
    document.addEventListener('visibilitychange', onChange);
    return () => {
      document.removeEventListener('visibilitychange', onChange);
    };
  }, []);

  return visible;
}
