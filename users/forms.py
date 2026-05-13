from django import forms
from .models import UserRegistrationModel


class UserRegistrationForm(forms.ModelForm):
    name = forms.CharField(widget=forms.TextInput(attrs={'pattern': '[a-zA-Z]+'}), required=True, max_length=100)
    loginid = forms.CharField(widget=forms.TextInput(attrs={'pattern': '[a-zA-Z]+'}), required=True, max_length=100)
    password = forms.CharField(widget=forms.PasswordInput(attrs={'pattern': '(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}',
                                                                 'title': 'Must contain at least one number and one uppercase and lowercase letter, and at least 8 or more characters'}),
                               required=True, max_length=100)
    mobile = forms.CharField(widget=forms.TextInput(attrs={'pattern': '[56789][0-9]{9}'}), required=True,
                             max_length=100)
    email = forms.CharField(widget=forms.TextInput(attrs={'pattern': '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'}),
                            required=True, max_length=100)
    locality = forms.CharField(widget=forms.TextInput(), required=True, max_length=100)
    address = forms.CharField(widget=forms.Textarea(attrs={'rows': 4, 'cols': 22}), required=True, max_length=250)
    city = forms.CharField(widget=forms.TextInput(
        attrs={'autocomplete': 'off', 'pattern': '[A-Za-z ]+', 'title': 'Enter Characters Only '}), required=True,
        max_length=100)
    state = forms.CharField(widget=forms.TextInput(
        attrs={'autocomplete': 'off', 'pattern': '[A-Za-z ]+', 'title': 'Enter Characters Only '}), required=True,
        max_length=100)
    status = forms.CharField(widget=forms.HiddenInput(), initial='waiting', max_length=100)

    class Meta():
        model = UserRegistrationModel
        fields = '__all__'


class ShipConfigForm(forms.Form):
    max_simulation_time = forms.FloatField(label="Simulation duration (hours)", initial=24, min_value=1)
    time_step = forms.FloatField(label="Time step (minutes)", initial=5, min_value=0.1)
    ship_type = forms.CharField(label="Ship type", initial="Cargo Vessel")
    max_speed = forms.FloatField(label="Maximum speed (knots)", initial=20.0)
    fuel_capacity = forms.FloatField(label="Initial fuel level (%)", initial=100.0, min_value=0, max_value=100)
    battery_capacity = forms.FloatField(label="Battery capacity (kWh)", initial=100.0)
    solar_panel_capacity = forms.FloatField(label="Solar panel capacity (kW)", initial=50.0)
    wind_turbine_capacity = forms.FloatField(label="Wind turbine capacity (kW)", initial=30.0)
    initial_battery_level = forms.FloatField(label="Initial battery level (%)", initial=80.0, min_value=0,
                                             max_value=100)
    communication_range = forms.FloatField(label="Communication range (nautical miles)", initial=50.0)
    initial_satellite_signal = forms.FloatField(label="Initial satellite signal (%)", initial=85.0, min_value=0,
                                                max_value=100)
    initial_cellular_signal = forms.FloatField(label="Initial cellular signal (%)", initial=70.0, min_value=0,
                                               max_value=100)
    weather_condition = forms.ChoiceField(choices=[('sunny', 'Sunny'), ('cloudy', 'Cloudy'), ('stormy', 'Stormy')],
                                          initial='sunny')
    wind_speed = forms.FloatField(label="Average wind speed (m/s)", initial=10.0)
    sea_condition = forms.ChoiceField(choices=[('calm', 'Calm'), ('moderate', 'Moderate'), ('rough', 'Rough')],
                                      initial='calm')


SECURITY_DOMAINS = [
    ('malware', 'Malware'),
    ('phishing', 'Phishing'),
    ('ddos', 'DDoS'),
    ('ransomware', 'Ransomware'),
    ('apt', 'APT'),
    ('insider_threat', 'Insider Threat'),
    ('zero_day', 'Zero Day'),
    ('supply_chain', 'Supply Chain'),
]

class OrgInputForm(forms.Form):
    name = forms.CharField(
        label='Organization Name',
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'border border-gray-300 rounded-md p-2 w-full focus:outline-none focus:ring-2 focus:ring-blue-500',
            'placeholder': 'Enter organization name'
        })
    )

    infrastructure_profile = forms.CharField(
        label='Technologies (comma-separated)',
        widget=forms.TextInput(attrs={
            'class': 'border border-gray-300 rounded-md p-2 w-full focus:outline-none focus:ring-2 focus:ring-blue-500',
            'placeholder': 'e.g. web,cloud,mobile'
        })
    )

    security_domains = forms.MultipleChoiceField(
        choices=SECURITY_DOMAINS,
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'space-y-2'
        }),
        label="Security Domains"
    )

    threat_data_quality = forms.FloatField(
        min_value=0,
        max_value=1,
        widget=forms.NumberInput(attrs={
            'class': 'border border-gray-300 rounded-md p-2 w-full focus:outline-none focus:ring-2 focus:ring-blue-500'
        })
    )

    sharing_willingness = forms.FloatField(
        min_value=0,
        max_value=1,
        widget=forms.NumberInput(attrs={
            'class': 'border border-gray-300 rounded-md p-2 w-full focus:outline-none focus:ring-2 focus:ring-blue-500'
        })
    )


# ─────────────────────────────────────────────────────────────────────────────
# ALLOWED EVIDENCE FILE EXTENSIONS
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_EVIDENCE_EXTENSIONS = [
    '.txt', '.log', '.csv', '.json',   # beginner-friendly
    '.pcap',                            # network capture (Wireshark)
    '.E01', '.dd',                      # disk images (Autopsy / FTK)
]

def validate_evidence_file(file):
    """
    Validator: reject files whose extension is not in ALLOWED_EVIDENCE_EXTENSIONS.
    Also enforces a 50 MB size limit.
    """
    import os
    from django.core.exceptions import ValidationError

    max_size_mb = 50
    ext = os.path.splitext(file.name)[1].lower()

    # .E01 is upper-case by convention – keep original extension for the check
    ext_original = os.path.splitext(file.name)[1]
    allowed_lower = [e.lower() for e in ALLOWED_EVIDENCE_EXTENSIONS]

    if ext_original not in ALLOWED_EVIDENCE_EXTENSIONS and ext not in allowed_lower:
        raise ValidationError(
            f"Unsupported file type '{ext_original}'. "
            f"Allowed types: {', '.join(ALLOWED_EVIDENCE_EXTENSIONS)}"
        )

    if file.size > max_size_mb * 1024 * 1024:
        raise ValidationError(f"File too large. Maximum allowed size is {max_size_mb} MB.")


class InvestigationForm(forms.Form):
    # ── Basic Case Information ────────────────────────────────────────────────
    case_id = forms.CharField(
        label="Case ID",
        max_length=50,
        widget=forms.TextInput(attrs={"placeholder": "EX12345"})
    )
    case_name = forms.CharField(
        label="Case Name",
        max_length=100,
        widget=forms.TextInput(attrs={"placeholder": "Unauthorized Access Investigation"})
    )
    investigator = forms.CharField(
        label="Investigator",
        max_length=100,
        widget=forms.TextInput(attrs={"placeholder": "John Doe"})
    )

    # ── Case Details ─────────────────────────────────────────────────────────
    description = forms.CharField(
        label="Case Description",
        widget=forms.Textarea(attrs={"placeholder": "Describe the case briefly..."})
    )
    jurisdiction = forms.CharField(
        label="Jurisdiction",
        widget=forms.TextInput(attrs={"placeholder": "United States, California"})
    )
    team_members = forms.CharField(
        label="Team Members",
        help_text="Comma-separated names",
        widget=forms.TextInput(attrs={"placeholder": "Alice, Bob, Charlie"})
    )
    legal_requirements = forms.CharField(
        label="Legal Requirements",
        help_text="Comma-separated requirements",
        widget=forms.TextInput(attrs={"placeholder": "GDPR, HIPAA"})
    )
    tools_used = forms.CharField(
        label="Tools Used",
        help_text="Comma-separated tool names",
        widget=forms.TextInput(attrs={"placeholder": "EnCase, FTK, Wireshark"})
    )

    # ── Evidence Information ──────────────────────────────────────────────────
    evidence_type = forms.ChoiceField(
        choices=[
            ('computer', 'Computer'),
            ('network_logs', 'Network Logs'),
            ('mobile_device', 'Mobile Device'),
            ('cloud_services', 'Cloud Services'),
        ],
        label="Type of Evidence"
    )
    evidence_source = forms.CharField(
        label="Evidence Source",
        widget=forms.TextInput(attrs={"placeholder": "Workstation 12, Router 3, iPhone 13"})
    )
    evidence_location = forms.CharField(
        label="Evidence Location",
        widget=forms.TextInput(attrs={"placeholder": "Building A, 2nd Floor, Office 12"})
    )

    # ── Evidence File Upload (replaces the old evidence_description textarea) ─
    evidence_file = forms.FileField(
        label="Upload Evidence File",
        help_text=(
            "Supported formats: .txt, .log, .csv, .json  (system/application logs)  |  "
            ".pcap  (network capture)  |  .E01, .dd  (disk images).  "
            "Max size: 50 MB."
        ),
        validators=[validate_evidence_file],
        widget=forms.ClearableFileInput(attrs={
            "accept": ".txt,.log,.csv,.json,.pcap,.E01,.dd",
            "class": "form-control",
        })
    )
