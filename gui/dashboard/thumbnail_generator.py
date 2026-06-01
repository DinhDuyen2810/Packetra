"""
Phase 8: Thumbnail Generation

Generates visual previews (thumbnails) of dashboards for gallery display.
"""

import io
from typing import Optional, Tuple
from PIL import Image, ImageDraw, ImageFont
from gui.dashboard import Dashboard, DashboardWidget, VisualizationType


class ThumbnailGenerator:
    """
    Generate thumbnail images for dashboard cards.
    
    Creates simple visual representations showing:
    - Dashboard name
    - Grid layout with widget placeholders
    - Color-coded visualization types
    """
    
    # Visualization type colors
    VIZ_COLORS = {
        VisualizationType.METRIC: (52, 152, 219),      # Blue
        VisualizationType.TABLE: (46, 204, 113),       # Green
        VisualizationType.BAR: (155, 89, 182),         # Purple
        VisualizationType.LINE: (230, 126, 34),        # Orange
        VisualizationType.AREA: (241, 196, 15),        # Yellow
        VisualizationType.PIE: (231, 76, 60),          # Red
        VisualizationType.DONUT: (230, 126, 34),       # Orange
        VisualizationType.HISTOGRAM: (52, 152, 219),   # Blue
        VisualizationType.HEATMAP: (155, 89, 182),     # Purple
        VisualizationType.TOPOLOGY: (46, 204, 113),    # Green
    }
    
    DEFAULT_SIZE = (320, 240)  # Width x Height in pixels
    GRID_COLS = 12
    GRID_ROWS = 4
    
    @staticmethod
    def generate(dashboard: Dashboard, size: Tuple[int, int] = DEFAULT_SIZE) -> Image.Image:
        """
        Generate thumbnail image for a dashboard.
        
        Args:
            dashboard: Dashboard to thumbnail
            size: (width, height) in pixels
        
        Returns:
            PIL Image object
        """
        width, height = size
        
        # Create image with white background
        img = Image.new('RGB', (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)
        
        # Draw border
        draw.rectangle([0, 0, width-1, height-1], outline=(200, 200, 200), width=2)
        
        # Draw title area
        title_height = 30
        draw.rectangle([0, 0, width, title_height], fill=(240, 240, 240))
        
        # Draw dashboard name (truncate if too long)
        title = dashboard.name[:20]
        if len(dashboard.name) > 20:
            title += "..."
        
        try:
            # Try to use default font, fallback to default if not available
            title_font = ImageFont.load_default()
            draw.text((5, 7), title, fill=(0, 0, 0), font=title_font)
        except:
            draw.text((5, 7), title, fill=(0, 0, 0))
        
        # Draw grid representation
        cell_width = width / ThumbnailGenerator.GRID_COLS
        cell_height = (height - title_height) / ThumbnailGenerator.GRID_ROWS
        
        # Create a grid of placeholder cells
        for row in range(ThumbnailGenerator.GRID_ROWS):
            for col in range(ThumbnailGenerator.GRID_COLS):
                x1 = col * cell_width
                y1 = title_height + row * cell_height
                x2 = x1 + cell_width
                y2 = y1 + cell_height
                
                # Draw light grid lines
                draw.rectangle([x1, y1, x2, y2], outline=(230, 230, 230), width=1)
        
        # Draw widget placeholders
        if dashboard.widgets:
            for widget in dashboard.widgets[:6]:  # Limit to 6 visible widgets
                # Get widget position
                layout = widget.layout
                x_cell = layout.x
                y_cell = layout.y
                width_cells = layout.w
                height_cells = layout.h
                
                # Convert to pixel coordinates
                px1 = x_cell * cell_width
                py1 = title_height + y_cell * cell_height
                px2 = px1 + width_cells * cell_width
                py2 = py1 + height_cells * cell_height
                
                # Skip if outside bounds
                if px1 >= width or py1 >= height:
                    continue
                
                # Get color based on visualization type
                viz_type = widget.visualization.type if widget.visualization else VisualizationType.METRIC
                color = ThumbnailGenerator.VIZ_COLORS.get(viz_type, (100, 100, 100))
                
                # Draw widget placeholder
                draw.rectangle(
                    [px1+1, py1+1, min(px2-1, width-1), min(py2-1, height-1)],
                    fill=color,
                    outline=color,
                    width=1
                )
        
        return img
    
    @staticmethod
    def save_thumbnail(dashboard: Dashboard, file_path: str, size: Tuple[int, int] = DEFAULT_SIZE) -> str:
        """
        Generate and save thumbnail to file.
        
        Args:
            dashboard: Dashboard to thumbnail
            file_path: Path to save PNG file
            size: Thumbnail size
        
        Returns:
            Path where thumbnail was saved
        """
        img = ThumbnailGenerator.generate(dashboard, size)
        img.save(file_path, format='PNG')
        return file_path
    
    @staticmethod
    def generate_png_bytes(dashboard: Dashboard, size: Tuple[int, int] = DEFAULT_SIZE) -> bytes:
        """
        Generate thumbnail and return as PNG bytes.
        
        Useful for embedding in JSON or sending over network.
        
        Args:
            dashboard: Dashboard to thumbnail
            size: Thumbnail size
        
        Returns:
            PNG image data as bytes
        """
        img = ThumbnailGenerator.generate(dashboard, size)
        
        # Save to bytes buffer
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        return buffer.getvalue()


class DashboardThumbnailCache:
    """
    Cache for dashboard thumbnails to avoid regeneration.
    
    Stores generated thumbnails in memory with optional file persistence.
    """
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize thumbnail cache.
        
        Args:
            cache_dir: Optional directory to persist thumbnails
        """
        self.cache_dir = cache_dir
        self.cache: dict = {}
    
    def get(self, dashboard_id: str) -> Optional[Image.Image]:
        """Get cached thumbnail"""
        return self.cache.get(dashboard_id)
    
    def set(self, dashboard_id: str, dashboard: Dashboard):
        """Generate and cache thumbnail"""
        try:
            img = ThumbnailGenerator.generate(dashboard)
            self.cache[dashboard_id] = img
            
            # Optionally persist to file
            if self.cache_dir:
                import os
                from pathlib import Path
                
                Path(self.cache_dir).mkdir(parents=True, exist_ok=True)
                file_path = os.path.join(self.cache_dir, f"{dashboard_id}.png")
                ThumbnailGenerator.save_thumbnail(dashboard, file_path)
        except Exception as e:
            print(f"Error generating thumbnail: {e}")
    
    def clear(self, dashboard_id: Optional[str] = None):
        """Clear cache entry or entire cache"""
        if dashboard_id:
            self.cache.pop(dashboard_id, None)
        else:
            self.cache.clear()
    
    def has(self, dashboard_id: str) -> bool:
        """Check if thumbnail is cached"""
        return dashboard_id in self.cache
