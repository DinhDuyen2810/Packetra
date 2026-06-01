"""
Dashboard Overview Gallery UI.

Displays dashboard templates and user dashboards as card grid with search/filter/sort.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QWidget, QScrollArea, QGridLayout,
    QPushButton, QLineEdit, QComboBox, QLabel, QFrame, QMessageBox, QInputDialog,
    QSizePolicy, QStackedWidget,
    QMenu, QApplication
)
from PySide6.QtCore import Qt, Signal, QSize, QTimer
from PySide6.QtGui import QIcon, QPixmap, QColor, QFont
from typing import List, Callable, Optional
import json

from .models import Dashboard, DashboardSummary, DashboardLayout, dashboard_to_summary
from .repository import DashboardRepository, DashboardTemplateRepository


class DashboardCard(QFrame):
    """A card widget displaying a dashboard summary"""

    clicked = Signal(str)
    double_clicked = Signal(str)  # dashboard ID - emitted on double-click
    use_template_clicked = Signal(str)
    more_clicked = Signal(str, QWidget)  # dashboard ID, widget position
    
    def __init__(self, summary: DashboardSummary, is_template: bool = False,
                 preview_widget: Optional[QWidget] = None, subtitle: Optional[str] = None):
        super().__init__()
        self.summary = summary
        self.is_template = is_template
        self.preview_widget = preview_widget
        self.subtitle = subtitle
        self.setup_ui()
    
    def setup_ui(self):
        """Build card UI"""
        self.setFrameShape(QFrame.Box)
        self.setFrameShadow(QFrame.Raised)
        self.setLineWidth(1)
        self.setStyleSheet("""
            DashboardCard {
                background-color: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 12px;
            }
            DashboardCard:hover {
                border: 1px solid #0066cc;
                background-color: #fafafa;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Header: title + more button
        header_layout = QHBoxLayout()
        title_label = QLabel(self.summary.name)
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(11)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        if not self.is_template:
            more_btn = QPushButton("⋮")
            more_btn.setMaximumWidth(32)
            more_btn.clicked.connect(lambda: self.more_clicked.emit(self.summary.id, more_btn))
            header_layout.addWidget(more_btn)
        
        layout.addLayout(header_layout)
        
        # Description
        if self.summary.description:
            desc_label = QLabel(self.summary.description)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("color: #666; font-size: 9pt;")
            layout.addWidget(desc_label)

        if self.subtitle:
            subtitle_label = QLabel(self.subtitle)
            subtitle_label.setStyleSheet("color: #999; font-size: 8pt;")
            subtitle_label.setWordWrap(True)
            layout.addWidget(subtitle_label)
        
        # Thumbnail / live preview
        thumbnail_frame = QFrame()
        thumbnail_frame.setStyleSheet("background-color: #e8e8e8; border: 1px solid #ccc; border-radius: 2px;")
        thumbnail_frame.setMinimumHeight(100)
        thumbnail_layout = QVBoxLayout(thumbnail_frame)
        thumbnail_layout.setContentsMargins(4, 4, 4, 4)
        if self.preview_widget is not None:
            self.preview_widget.setParent(thumbnail_frame)
            thumbnail_layout.addWidget(self.preview_widget)
        else:
            placeholder_label = QLabel("Preview unavailable")
            placeholder_label.setAlignment(Qt.AlignCenter)
            placeholder_label.setStyleSheet("color: #888; font-size: 9pt;")
            thumbnail_layout.addWidget(placeholder_label)
        layout.addWidget(thumbnail_frame)
        
        # Stats
        stats_layout = QHBoxLayout()
        
        widgets_label = QLabel(f"Widgets: {self.summary.widget_count}")
        widgets_label.setStyleSheet("font-size: 9pt; color: #333;")
        stats_layout.addWidget(widgets_label)
        
        types_str = ", ".join(self.summary.visualization_types[:3])
        if len(self.summary.visualization_types) > 3:
            types_str += "..."
        types_label = QLabel(f"Types: {types_str}")
        types_label.setStyleSheet("font-size: 9pt; color: #666;")
        stats_layout.addWidget(types_label)
        
        stats_layout.addStretch()
        
        updated_label = QLabel(f"Updated: {self.summary.updated_at[:10]}")
        updated_label.setStyleSheet("font-size: 8pt; color: #999;")
        stats_layout.addWidget(updated_label)
        
        layout.addLayout(stats_layout)
        
        # Badge
        badge_layout = QHBoxLayout()
        badge_text = "Template" if self.summary.is_template else "Custom"
        if self.summary.source_template_id and not self.summary.is_template:
            badge_text = "Custom (from template)"
        
        badge_label = QLabel(f"[{badge_text}]")
        badge_label.setStyleSheet(f"font-size: 8pt; color: #0066cc; font-weight: bold;")
        badge_layout.addWidget(badge_label)
        badge_layout.addStretch()
        layout.addLayout(badge_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        if self.is_template:
            use_btn = QPushButton("Use Template")
            use_btn.setMinimumHeight(32)
            use_btn.clicked.connect(lambda: self.use_template_clicked.emit(self.summary.id))
            button_layout.addWidget(use_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        layout.addStretch()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.summary.id)
        super().mousePressEvent(event)
    
    def mouseDoubleClickEvent(self, event):
        """Handle double-click to open dashboard"""
        self.double_clicked.emit(self.summary.id)
        super().mouseDoubleClickEvent(event)
    
    def get_context_menu_position(self) -> QSize:
        """For positioning context menu"""
        return self.geometry().bottomRight()


class DashboardOverviewDialog(QDialog):
    """Main dialog for dashboard overview/gallery"""
    
    dashboard_opened = Signal(str)  # dashboard ID
    dashboard_created = Signal()
    
    def __init__(self, template_repo: DashboardTemplateRepository, dashboard_repo: DashboardRepository, 
                 query_engine=None, viz_registry=None, parent=None):
        super().__init__(parent)
        self.template_repo = template_repo
        self.dashboard_repo = dashboard_repo
        self.query_engine = query_engine
        self.viz_registry = viz_registry
        self.setWindowTitle("Dashboard")
        self.setGeometry(100, 100, 1200, 900)
        
        # Filter and sort state
        self.current_filter = "all"  # all, templates, my_dashboards
        self.current_sort = "recently_updated"
        self.search_text = ""
        self.detail_dashboard: Optional[Dashboard] = None
        self.detail_is_template = False
        self.detail_display_mode = "chart"
        
        self.setup_ui()
        self._apply_fixed_screen_size()
        self.load_dashboards()

    def _apply_fixed_screen_size(self):
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        available = screen.availableGeometry()
        width = int(available.width() * 0.9)
        height = int(available.height() * 0.9)
        self.setFixedSize(width, height)
        self.move(
            available.x() + ((available.width() - width) // 2),
            available.y() + ((available.height() - height) // 2),
        )
    
    def setup_ui(self):
        """Build main UI"""
        main_layout = QVBoxLayout(self)

        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack)

        self.gallery_page = QWidget()
        gallery_layout = QVBoxLayout(self.gallery_page)

        # Header with title and create button
        header_layout = QHBoxLayout()
        title_label = QLabel("Dashboard")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        import_btn = QPushButton("Import Dashboard")
        import_btn.clicked.connect(self.on_import_dashboard)
        header_layout.addWidget(import_btn)
        
        create_btn = QPushButton("Create Dashboard")
        create_btn.clicked.connect(self.on_create_dashboard)
        header_layout.addWidget(create_btn)
        
        gallery_layout.addLayout(header_layout)
        
        # Search/filter/sort toolbar
        toolbar_layout = QHBoxLayout()
        
        search_label = QLabel("Search:")
        toolbar_layout.addWidget(search_label)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search dashboards...")
        self.search_input.setMaximumWidth(250)
        self.search_input.textChanged.connect(self.on_search_changed)
        toolbar_layout.addWidget(self.search_input)
        
        toolbar_layout.addSpacing(20)
        
        filter_label = QLabel("View:")
        toolbar_layout.addWidget(filter_label)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Templates", "My Dashboards"])
        self.filter_combo.currentTextChanged.connect(self.on_filter_changed)
        self.filter_combo.setMaximumWidth(150)
        toolbar_layout.addWidget(self.filter_combo)
        
        toolbar_layout.addSpacing(20)
        
        sort_label = QLabel("Sort:")
        toolbar_layout.addWidget(sort_label)
        
        self.sort_combo = QComboBox()
        self.sort_combo.addItems(["Recently Updated", "Name (A-Z)", "Name (Z-A)", "Created Date"])
        self.sort_combo.currentTextChanged.connect(self.on_sort_changed)
        self.sort_combo.setMaximumWidth(150)
        toolbar_layout.addWidget(self.sort_combo)
        
        toolbar_layout.addStretch()
        gallery_layout.addLayout(toolbar_layout)
        
        # Scroll area with dashboards
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        
        # Templates section
        self.templates_label = QLabel("Chart Templates")
        templates_font = QFont()
        templates_font.setBold(True)
        templates_font.setPointSize(11)
        self.templates_label.setFont(templates_font)
        self.content_layout.addWidget(self.templates_label)
        
        self.templates_grid_widget = QWidget()
        self.templates_grid = QGridLayout(self.templates_grid_widget)
        self.templates_grid.setSpacing(12)
        self.content_layout.addWidget(self.templates_grid_widget)
        
        # User dashboards section
        self.user_label = QLabel("My Dashboards")
        user_font = QFont()
        user_font.setBold(True)
        user_font.setPointSize(11)
        self.user_label.setFont(user_font)
        self.content_layout.addWidget(self.user_label)
        
        self.user_grid_widget = QWidget()
        self.user_grid = QGridLayout(self.user_grid_widget)
        self.user_grid.setSpacing(12)
        self.content_layout.addWidget(self.user_grid_widget)
        
        self.content_layout.addStretch()
        scroll_area.setWidget(self.content_widget)
        gallery_layout.addWidget(scroll_area)

        self.stack.addWidget(self.gallery_page)

        self.detail_page = QWidget()
        detail_layout = QVBoxLayout(self.detail_page)

        detail_header = QHBoxLayout()
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.show_gallery_page)
        detail_header.addWidget(self.back_button)

        self.detail_title_label = QLabel("")
        detail_title_font = QFont()
        detail_title_font.setPointSize(14)
        detail_title_font.setBold(True)
        self.detail_title_label.setFont(detail_title_font)
        detail_header.addWidget(self.detail_title_label)

        detail_header.addStretch()

        self.detail_action_button = QPushButton("")
        self.detail_action_button.clicked.connect(self.on_detail_action)
        detail_header.addWidget(self.detail_action_button)

        detail_layout.addLayout(detail_header)

        self.detail_description_label = QLabel("")
        self.detail_description_label.setWordWrap(True)
        self.detail_description_label.setStyleSheet("color: #666; font-size: 10pt;")
        detail_layout.addWidget(self.detail_description_label)

        detail_controls = QHBoxLayout()
        self.detail_source_label = QLabel("")
        self.detail_source_label.setStyleSheet("color: #888; font-size: 9pt;")
        detail_controls.addWidget(self.detail_source_label)
        detail_controls.addStretch()

        self.detail_view_mode_combo = QComboBox()
        self.detail_view_mode_combo.addItems(["Chart", "Table"])
        self.detail_view_mode_combo.currentTextChanged.connect(self.on_detail_view_mode_changed)
        detail_controls.addWidget(QLabel("View:"))
        detail_controls.addWidget(self.detail_view_mode_combo)
        detail_layout.addLayout(detail_controls)

        self.detail_preview_frame = QFrame()
        self.detail_preview_frame.setStyleSheet("background-color: #f8f8f8; border: 1px solid #ddd; border-radius: 6px;")
        self.detail_preview_layout = QVBoxLayout(self.detail_preview_frame)
        self.detail_preview_layout.setContentsMargins(12, 12, 12, 12)
        detail_layout.addWidget(self.detail_preview_frame, 1)

        self.stack.addWidget(self.detail_page)
        self.stack.setCurrentWidget(self.gallery_page)
    
    def load_dashboards(self):
        """Load templates and user dashboards"""
        self.clear_grids()
        
        # Load templates
        templates = self.template_repo.list_chart_template_dashboards()
        self.filtered_templates = self.filter_dashboards(templates, is_template=True)
        
        # Load user dashboards
        user_dashboards = self.dashboard_repo.get_summaries()
        self.filtered_user_dashboards = self.filter_dashboards(user_dashboards, is_template=False)
        
        self.render_templates()
        self.render_user_dashboards()
        self.update_section_visibility()
    
    def filter_dashboards(self, dashboards: List[DashboardSummary], is_template: bool = False) -> List[DashboardSummary]:
        """Apply search filter"""
        if not self.search_text:
            return dashboards
        
        search_lower = self.search_text.lower()
        filtered = []
        
        for d in dashboards:
            if (search_lower in d.name.lower() or
                (d.description and search_lower in d.description.lower()) or
                any(search_lower in tag for tag in d.tags)):
                filtered.append(d)
        
        return filtered
    
    def sort_dashboards(self, dashboards: List[DashboardSummary]) -> List[DashboardSummary]:
        """Apply sorting"""
        sort_text = self.sort_combo.currentText()
        
        if sort_text == "Recently Updated":
            return sorted(dashboards, key=lambda d: d.updated_at, reverse=True)
        elif sort_text == "Name (A-Z)":
            return sorted(dashboards, key=lambda d: d.name)
        elif sort_text == "Name (Z-A)":
            return sorted(dashboards, key=lambda d: d.name, reverse=True)
        elif sort_text == "Created Date":
            return sorted(dashboards, key=lambda d: d.created_at, reverse=True)
        
        return dashboards
    
    def clear_grids(self):
        """Clear all cards from grids"""
        for i in reversed(range(self.templates_grid.count())):
            item = self.templates_grid.takeAt(i)
            if item and item.widget():
                item.widget().deleteLater()
        
        for i in reversed(range(self.user_grid.count())):
            item = self.user_grid.takeAt(i)
            if item and item.widget():
                item.widget().deleteLater()
    
    def render_templates(self):
        """Render template cards"""
        templates = self.sort_dashboards(self.filtered_templates)
        
        if not templates:
            no_templates_label = QLabel("No templates available")
            no_templates_label.setStyleSheet("color: #999;")
            self.templates_grid.addWidget(no_templates_label, 0, 0)
            self.templates_grid_widget.setVisible(True)
            return
        
        self.templates_grid_widget.setVisible(True)
        
        for idx, template_dashboard in enumerate(templates):
            summary = dashboard_to_summary(template_dashboard)
            card = DashboardCard(
                summary,
                is_template=True,
                preview_widget=self._create_preview_widget(template_dashboard),
                subtitle="Click to preview here. Use Template to add this chart to your dashboards.",
            )
            card.clicked.connect(self.on_view_template)
            card.use_template_clicked.connect(self.on_use_template)
            card.double_clicked.connect(self.on_view_template)
            
            col = idx % 3
            row = idx // 3
            self.templates_grid.addWidget(card, row, col)
        
        for col in range(3):
            self.templates_grid.setColumnStretch(col, 1)
    
    def render_user_dashboards(self):
        """Render user dashboard cards"""
        user_dashboards = self.sort_dashboards(self.filtered_user_dashboards)
        
        if not user_dashboards:
            no_dash_label = QLabel("No custom dashboards yet.\nStart from a template or create a blank dashboard.")
            no_dash_label.setStyleSheet("color: #999; qproperty-alignment: AlignCenter;")
            self.user_grid.addWidget(no_dash_label, 0, 0)
            self.user_grid_widget.setVisible(True)
            return
        
        self.user_grid_widget.setVisible(True)
        
        for idx, dashboard in enumerate(user_dashboards):
            dashboard_model = self.dashboard_repo.load(dashboard.id)
            card = DashboardCard(
                dashboard,
                is_template=False,
                preview_widget=self._create_dashboard_preview_widget(dashboard_model) if dashboard_model else None,
                subtitle="Miniature of your full dashboard. Click to open it directly.",
            )
            card.clicked.connect(self.on_open_dashboard)
            card.double_clicked.connect(self.on_open_dashboard)
            card.more_clicked.connect(self.on_card_more_clicked)
            
            col = idx % 3
            row = idx // 3
            self.user_grid.addWidget(card, row, col)
        
        # Fill remaining columns with stretch
        for col in range(3):
            self.user_grid.setColumnStretch(col, 1)

    def update_section_visibility(self):
        """Toggle section visibility based on the current view filter."""
        show_templates = self.current_filter in {"all", "templates"}
        show_user_dashboards = self.current_filter in {"all", "my_dashboards"}

        self.templates_label.setVisible(show_templates)
        self.templates_grid_widget.setVisible(show_templates)
        self.user_label.setVisible(show_user_dashboards)
        self.user_grid_widget.setVisible(show_user_dashboards)

    def _open_editor(self, dashboard: Dashboard, dashboard_repo):
        """Open the dashboard editor after closing the overview to avoid Qt chart crashes."""
        from .dashboard_editor import DashboardEditor

        owner = self.parentWidget() or QApplication.instance()
        if owner is not None and not hasattr(owner, "_dashboard_editor_windows"):
            setattr(owner, "_dashboard_editor_windows", [])
        editor_windows = getattr(owner, "_dashboard_editor_windows", None)
        if owner is not None and not hasattr(owner, "_dashboard_overview_windows"):
            setattr(owner, "_dashboard_overview_windows", [])
        overview_windows = getattr(owner, "_dashboard_overview_windows", None)

        dashboard_model = dashboard
        dashboard_repository = dashboard_repo
        query_engine = self.query_engine
        viz_registry = self.viz_registry
        template_repo = self.template_repo

        def reopen_overview():
            overview = DashboardOverviewDialog(
                template_repo=template_repo,
                dashboard_repo=dashboard_repository,
                query_engine=query_engine,
                viz_registry=viz_registry,
                parent=owner if isinstance(owner, QWidget) else None,
            )
            overview.setAttribute(Qt.WA_DeleteOnClose, True)
            if overview_windows is not None:
                overview_windows.append(overview)

                def release_overview(*_args, window=overview):
                    if window in overview_windows:
                        overview_windows.remove(window)

                overview.finished.connect(release_overview)

            overview.show()
            overview.raise_()
            overview.activateWindow()

        def launch_editor():
            editor = DashboardEditor(
                dashboard=dashboard_model,
                dashboard_repo=dashboard_repository,
                query_engine=query_engine,
                viz_registry=viz_registry,
                template_repo=template_repo,
                back_callback=reopen_overview,
                parent=None,
            )
            editor.setAttribute(Qt.WA_DeleteOnClose, True)
            if editor_windows is not None:
                editor_windows.append(editor)

                def release_editor(*_args, window=editor):
                    if window in editor_windows:
                        editor_windows.remove(window)

                editor.finished.connect(release_editor)

            editor.show()
            editor.raise_()
            editor.activateWindow()

        QTimer.singleShot(0, launch_editor)
        self.accept()

    def _preview_config(self, widget_model, *, compact_mode: bool = True, display_mode: Optional[str] = None) -> dict:
        visualization = widget_model.visualization
        config = {
            "type": visualization.type,
            "xField": visualization.x_field,
            "yField": visualization.y_field,
            "categoryField": visualization.category_field,
            "valueField": visualization.value_field,
            "seriesField": visualization.series_field,
            "showLegend": False,
            "showLabels": False,
            "compactMode": compact_mode,
        }
        if display_mode == "table":
            config["type"] = "table"
        return config

    def _make_preview_pass_through(self, widget: QWidget):
        widget.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        for child in widget.findChildren(QWidget):
            child.setAttribute(Qt.WA_TransparentForMouseEvents, True)

    def _clear_layout(self, layout):
        while layout.count() > 0:
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _create_preview_widget(
        self,
        dashboard: Optional[Dashboard],
        *,
        compact_mode: bool = True,
        fixed_height: Optional[int] = 120,
        pass_through: bool = True,
        display_mode: Optional[str] = None,
    ) -> Optional[QWidget]:
        if dashboard is None or not dashboard.widgets or not self.query_engine or not self.viz_registry:
            return None

        widget_model = dashboard.widgets[0]
        try:
            data = self.query_engine.execute(
                data_source=widget_model.data_source,
                query=widget_model.query,
                global_filter=None,
            )
            render_type = "table" if display_mode == "table" else widget_model.visualization.type
            renderer = self.viz_registry.get_renderer(render_type)
            if renderer is None:
                return None
            preview = renderer(
                data,
                self._preview_config(widget_model, compact_mode=compact_mode, display_mode=display_mode),
                None,
            )
            if fixed_height is not None:
                preview.setMinimumHeight(fixed_height)
                preview.setMaximumHeight(fixed_height)
                preview.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            else:
                preview.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            if pass_through:
                self._make_preview_pass_through(preview)
            return preview
        except Exception:
            return None

    def _create_dashboard_preview_widget(self, dashboard: Optional[Dashboard]) -> Optional[QWidget]:
        """Render a miniature of the whole dashboard instead of only the first widget."""
        if dashboard is None or not dashboard.widgets:
            return None
        if len(dashboard.widgets) == 1:
            return self._create_preview_widget(dashboard)

        preview = QWidget()
        preview_layout = QGridLayout(preview)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_layout.setSpacing(4)

        ordered_widgets = sorted(
            dashboard.widgets,
            key=lambda widget: (
                int(getattr(widget.layout, 'y', 0) or 0),
                int(getattr(widget.layout, 'x', 0) or 0),
                widget.id,
            ),
        )

        for widget_model in ordered_widgets:
            widget_dashboard = Dashboard(
                schema_version=dashboard.schema_version,
                dashboard_id=f"{dashboard.dashboard_id}:{widget_model.id}",
                name=widget_model.title,
                description=widget_model.description,
                is_template=dashboard.is_template,
                created_at=dashboard.created_at,
                updated_at=dashboard.updated_at,
                layout=dashboard.layout,
                widgets=[widget_model],
                source_template_id=dashboard.source_template_id,
                global_filter=dashboard.global_filter,
                time_range=dashboard.time_range,
                data_scope=dashboard.data_scope,
                tags=list(dashboard.tags),
                thumbnail=dashboard.thumbnail,
            )
            widget_preview = self._create_preview_widget(
                widget_dashboard,
                compact_mode=True,
                fixed_height=84,
                pass_through=True,
            )
            if widget_preview is None:
                widget_preview = QLabel(widget_model.title)
                widget_preview.setAlignment(Qt.AlignCenter)
                widget_preview.setStyleSheet("color: #888; font-size: 8pt;")

            frame = QFrame()
            frame.setStyleSheet("background-color: #ffffff; border: 1px solid #ddd; border-radius: 3px;")
            frame_layout = QVBoxLayout(frame)
            frame_layout.setContentsMargins(4, 4, 4, 4)
            frame_layout.setSpacing(2)
            frame_layout.addWidget(widget_preview)
            title = QLabel(widget_model.title)
            title.setStyleSheet("color: #666; font-size: 8pt;")
            title.setAlignment(Qt.AlignCenter)
            frame_layout.addWidget(title)
            layout = widget_model.layout
            preview_layout.addWidget(frame, layout.y, layout.x, layout.h, layout.w)

        return preview

    def _render_detail_dashboard(self):
        self._clear_layout(self.detail_preview_layout)
        if self.detail_dashboard is None:
            return

        preview = self._create_preview_widget(
            self.detail_dashboard,
            compact_mode=False,
            fixed_height=None,
            pass_through=False,
            display_mode=self.detail_display_mode,
        )
        if preview is None:
            placeholder = QLabel("Preview unavailable")
            placeholder.setAlignment(Qt.AlignCenter)
            placeholder.setStyleSheet("color: #999; font-size: 11pt;")
            self.detail_preview_layout.addWidget(placeholder)
            return

        preview.setMinimumHeight(max(420, int(self.height() * 0.5)))
        self.detail_preview_layout.addWidget(preview)

    def _show_dashboard_detail(self, dashboard: Dashboard, *, is_template: bool):
        self.detail_dashboard = dashboard
        self.detail_is_template = is_template
        self.detail_title_label.setText(dashboard.name)
        self.detail_description_label.setText(dashboard.description or "")
        self.detail_source_label.setText(f"Source: {dashboard.widgets[0].data_source}" if dashboard.widgets else "")
        self.detail_action_button.setText("Use Template" if is_template else "Open Dashboard")
        self.detail_action_button.setVisible(True)

        widget_type = dashboard.widgets[0].visualization.type if dashboard.widgets else "chart"
        self.detail_display_mode = "table" if widget_type == "table" else "chart"
        self.detail_view_mode_combo.setVisible(bool(dashboard.widgets))
        self.detail_view_mode_combo.blockSignals(True)
        self.detail_view_mode_combo.setCurrentText("Table" if self.detail_display_mode == "table" else "Chart")
        self.detail_view_mode_combo.blockSignals(False)

        self._render_detail_dashboard()
        self.stack.setCurrentWidget(self.detail_page)

    def show_gallery_page(self):
        self.stack.setCurrentWidget(self.gallery_page)

    def on_detail_view_mode_changed(self, text: str):
        self.detail_display_mode = "table" if text == "Table" else "chart"
        self._render_detail_dashboard()

    def on_detail_action(self):
        if self.detail_dashboard is None:
            return
        if self.detail_is_template:
            self.on_use_template(self.detail_dashboard.dashboard_id)
            return
        self.on_open_dashboard(self.detail_dashboard.dashboard_id)
    
    def on_search_changed(self, text: str):
        """Handle search input change"""
        self.search_text = text
        QTimer.singleShot(300, self.load_dashboards)
    
    def on_filter_changed(self, text: str):
        """Handle filter change"""
        filters = {
            "All": "all",
            "Templates": "templates",
            "My Dashboards": "my_dashboards"
        }
        self.current_filter = filters.get(text, "all")
        self.load_dashboards()
    
    def on_sort_changed(self, text: str):
        """Handle sort change"""
        self.load_dashboards()
    
    def on_use_template(self, template_id: str):
        """Create dashboard from template"""
        template_dashboard = self.template_repo.get_chart_template_dashboard(template_id)
        if not template_dashboard:
            QMessageBox.warning(self, "Error", "Template not found")
            return

        new_dashboard = self.template_repo.create_dashboard_from_chart_template(template_id, template_dashboard.name)
        if not new_dashboard:
            QMessageBox.warning(self, "Error", "Failed to create dashboard from template")
            return

        self._open_editor(new_dashboard, self.dashboard_repo)
    
    def on_open_dashboard(self, dashboard_id: str):
        """Open a user dashboard in the editor window."""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            QMessageBox.warning(self, "Error", "Dashboard not found")
            return

        self._open_editor(dashboard, self.dashboard_repo)

    def on_view_dashboard(self, dashboard_id: str):
        """Preview a user dashboard inline inside the overview dialog."""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            QMessageBox.warning(self, "Error", "Dashboard not found")
            return

        self._show_dashboard_detail(dashboard, is_template=False)
    
    def on_view_template(self, template_id: str):
        """Preview a template inline inside the overview dialog."""
        template = self.template_repo.get_chart_template_dashboard(template_id)
        if not template:
            QMessageBox.warning(self, "Error", "Template not found")
            return

        self._show_dashboard_detail(template, is_template=True)
    
    def on_card_more_clicked(self, dashboard_id: str, widget):
        """Show context menu for dashboard"""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return
        
        menu = QMenu(self)
        
        if not dashboard.is_template:
            rename_action = menu.addAction("Rename")
            rename_action.triggered.connect(lambda: self.on_rename_dashboard(dashboard_id))
            
            duplicate_action = menu.addAction("Duplicate")
            duplicate_action.triggered.connect(lambda: self.on_duplicate_dashboard(dashboard_id))
            
            export_action = menu.addAction("Export JSON")
            export_action.triggered.connect(lambda: self.on_export_dashboard(dashboard_id))
            
            menu.addSeparator()
            
            delete_action = menu.addAction("Delete")
            delete_action.triggered.connect(lambda: self.on_delete_dashboard(dashboard_id))
        
        menu.popup(widget.mapToGlobal(widget.rect().bottomRight()))
    
    def on_create_dashboard(self):
        """Create blank dashboard"""
        from uuid import uuid4
        from datetime import datetime

        name, ok = QInputDialog.getText(
            self,
            "Create Dashboard",
            "Dashboard name:",
            text="Untitled Dashboard"
        )
        if not ok:
            return

        dashboard_name = (name or '').strip() or "Untitled Dashboard"
        new_dashboard = Dashboard(
            schema_version=1,
            dashboard_id=str(uuid4()),
            name=dashboard_name,
            description=None,
            is_template=False,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[],
        )

        self._open_editor(new_dashboard, self.dashboard_repo)
    
    def on_import_dashboard(self):
        """Import dashboard from JSON"""
        from PySide6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Dashboard", "", "Dashboard JSON (*.json)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json_str = f.read()
            
            dashboard = self.dashboard_repo.import_json(json_str)
            if dashboard:
                QMessageBox.information(self, "Success", f"Imported dashboard '{dashboard.name}'")
                self.load_dashboards()
            else:
                QMessageBox.warning(self, "Error", "Failed to import dashboard")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import: {str(e)}")
    
    def on_rename_dashboard(self, dashboard_id: str):
        """Rename a dashboard"""
        from PySide6.QtWidgets import QInputDialog
        
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return
        
        new_name, ok = QInputDialog.getText(
            self, "Rename Dashboard", "New name:", text=dashboard.name
        )
        
        if ok and new_name:
            self.dashboard_repo.rename(dashboard_id, new_name)
            self.load_dashboards()
    
    def on_duplicate_dashboard(self, dashboard_id: str):
        """Duplicate a dashboard"""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return
        
        new_name = f"{dashboard.name} (Copy)"
        new_dashboard = self.dashboard_repo.duplicate(dashboard_id, new_name)
        
        if new_dashboard:
            QMessageBox.information(self, "Success", f"Duplicated dashboard '{new_name}'")
            self.load_dashboards()
    
    def on_export_dashboard(self, dashboard_id: str):
        """Export dashboard as JSON"""
        from PySide6.QtWidgets import QFileDialog
        
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Dashboard", f"{dashboard.name}.json", "Dashboard JSON (*.json)"
        )
        
        if file_path:
            json_str = self.dashboard_repo.export_json(dashboard_id)
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                QMessageBox.information(self, "Success", "Dashboard exported")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {str(e)}")
    
    def on_delete_dashboard(self, dashboard_id: str):
        """Delete a dashboard with confirmation"""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return
        
        reply = QMessageBox.question(
            self,
            "Delete Dashboard",
            f"Delete dashboard '{dashboard.name}'?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.Cancel
        )
        
        if reply == QMessageBox.Yes:
            self.dashboard_repo.delete(dashboard_id)
            QMessageBox.information(self, "Success", "Dashboard deleted")
            self.load_dashboards()
