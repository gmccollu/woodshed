<script lang="ts" module>
  // 24×24 stroke icons, drawn for Woodshed (no icon font, nothing fetched).
  const PATHS = {
    home: 'M3 11.5 12 4l9 7.5M5.5 9.5V20h13V9.5',
    devices: 'M4 5h16v10H4zM8 19h8M12 15v4',
    search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM16.5 16.5 21 21',
    export: 'M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19h14',
    settings:
      'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM19.4 13a7.6 7.6 0 0 0 0-2l2-1.5-2-3.4-2.3 1a7.4 7.4 0 0 0-1.7-1L15 3.6h-4l-.4 2.5a7.4 7.4 0 0 0-1.7 1l-2.3-1-2 3.4 2 1.5a7.6 7.6 0 0 0 0 2l-2 1.5 2 3.4 2.3-1a7.4 7.4 0 0 0 1.7 1l.4 2.5h4l.4-2.5a7.4 7.4 0 0 0 1.7-1l2.3 1 2-3.4z',
    about: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 11v6M12 7.5v.5',
    welcome: 'M5 21V4M5 4h11l-2 4 2 4H5',
    sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
    moon: 'M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z',
    pause: 'M9 5v14M15 5v14',
    play: 'M7 5l12 7-12 7z',
    copy: 'M9 9h10v11H9zM5 15V4h10',
    check: 'M5 12.5l4.5 4.5L19 7',
    edit: 'M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4',
    eye: 'M2 12s3.5-6.5 10-6.5S22 12 22 12s-3.5 6.5-10 6.5S2 12 2 12zM12 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z',
    eyeOff: 'M3 3l18 18M10.6 6.1A10 10 0 0 1 12 6c6.5 0 10 6 10 6a17 17 0 0 1-3 3.6M6.5 7.5C3.7 9.3 2 12 2 12s3.5 6 10 6a9.6 9.6 0 0 0 4.3-1M9.9 10a2.5 2.5 0 0 0 3.5 3.6',
    x: 'M6 6l12 12M18 6 6 18',
    plus: 'M12 5v14M5 12h14',
    trash: 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13',
    alert: 'M12 3 2 20h20zM12 10v4M12 17v.5',
    retry: 'M4 12a8 8 0 0 1 14-5.3M20 12a8 8 0 0 1-14 5.3M18 3v4h-4M6 21v-4h4',
    clear: 'M5 7h14M8 7v12h8V7M10 4h4',
    arrow: 'M5 12h14M13 6l6 6-6 6',
    logout: 'M14 4h5v16h-5M10 8l-4 4 4 4M6 12h10',
    expand: 'M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5',
    shrink: 'M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5',
    clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2',
    download: 'M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19h14',
    plug: 'M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0zM12 17v4',
    flask: 'M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4A2 2 0 0 0 19 18l-5-9V3',
  } as const;
  export type IconName = keyof typeof PATHS;
</script>

<script lang="ts">
  let { name, size = 18, label = '' }: { name: IconName; size?: number; label?: string } = $props();
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.8"
  stroke-linecap="round"
  stroke-linejoin="round"
  role={label ? 'img' : undefined}
  aria-label={label || undefined}
  aria-hidden={label ? undefined : 'true'}
  class="shrink-0"
>
  <path d={PATHS[name]} />
</svg>
