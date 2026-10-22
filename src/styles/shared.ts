import { makeStyles, tokens } from '@fluentui/react-components';

/**
 * Shared layout primitives used by every page: a consistent 8px spacing
 * rhythm, dense tables and card grids. Component-local styles stay in a
 * dedicated `useStyles` per file.
 */
export const useSharedStyles = makeStyles({
  page: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    padding: '16px 24px 32px 24px',
    minWidth: 0,
  },
  pageHeader: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: '16px',
    flexWrap: 'wrap',
  },
  pageTitleBlock: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
    minWidth: 0,
  },
  toolbar: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
    gap: '16px',
    alignItems: 'start',
  },
  gridWide: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))',
    gap: '16px',
    alignItems: 'start',
  },
  split: {
    display: 'grid',
    gridTemplateColumns: 'minmax(320px, 1fr) minmax(360px, 480px)',
    gap: '16px',
    alignItems: 'start',
    '@media (max-width: 1100px)': {
      gridTemplateColumns: '1fr',
    },
  },
  dense: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  mono: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
    overflowWrap: 'anywhere',
  },
  muted: {
    color: tokens.colorNeutralForeground3,
  },
  tableWrapper: {
    overflowX: 'auto',
  },
  scrollArea: {
    overflowY: 'auto',
    maxHeight: '480px',
  },
});
