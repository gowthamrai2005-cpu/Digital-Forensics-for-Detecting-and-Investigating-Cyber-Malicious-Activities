from django.db import models


# ─────────────────────────────────────────────────────────────────────────────
# EXISTING MODELS (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

class UserRegistrationModel(models.Model):
    name = models.CharField(max_length=100)
    loginid = models.CharField(unique=True, max_length=100)
    password = models.CharField(max_length=100)
    mobile = models.CharField(unique=True, max_length=100)
    email = models.CharField(unique=True, max_length=100)
    locality = models.CharField(max_length=100)
    address = models.CharField(max_length=1000)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    status = models.CharField(max_length=100)
    last_login = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.loginid

    class Meta:
        db_table = 'UserRegistrations'


class TokenCountModel(models.Model):
    loginid = models.CharField(unique=True, max_length=100)
    count = models.IntegerField()

    def __str__(self):
        return self.loginid

    class Meta:
        db_table = 'TokenCountTable'


class UserFilesModel(models.Model):
    username = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    filename = models.CharField(max_length=100)
    enckey = models.CharField(max_length=1000)
    file = models.FileField(upload_to='actual/')
    cdate = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        db_table = 'uploadeddata'


# ─────────────────────────────────────────────────────────────────────────────
# NEW: Evidence file upload model
# ─────────────────────────────────────────────────────────────────────────────

THREAT_LEVEL_CHOICES = [
    ('Low',      'Low'),
    ('Medium',   'Medium'),
    ('High',     'High'),
    ('Critical', 'Critical'),
    ('Unknown',  'Unknown'),
]

FILE_TYPE_CHOICES = [
    ('log',             'Log File (.txt / .log)'),
    ('csv',             'CSV Data (.csv)'),
    ('json',            'JSON Log (.json)'),
    ('network_capture', 'Network Capture (.pcap)'),
    ('disk_image',      'Disk Image (.E01 / .dd)'),
    ('unknown',         'Unknown'),
]


def evidence_upload_path(instance, filename):
    """Store uploaded evidence under  media/evidence_uploads/<case_id>/<filename>"""
    return f"evidence_uploads/{instance.case_id}/{filename}"


class EvidenceFileModel(models.Model):
    """
    Stores metadata + the uploaded file for each piece of digital evidence
    submitted via InvestigationForm.
    """
    case_id         = models.CharField(max_length=100, db_index=True)
    case_name       = models.CharField(max_length=200)
    investigator    = models.CharField(max_length=100)

    # Uploaded file
    evidence_file   = models.FileField(upload_to=evidence_upload_path)
    original_name   = models.CharField(max_length=255)       # e.g. "auth.log"
    file_size_kb    = models.FloatField(default=0.0)

    # Analysis results
    file_type       = models.CharField(max_length=50, choices=FILE_TYPE_CHOICES, default='unknown')
    threat_level    = models.CharField(max_length=20, choices=THREAT_LEVEL_CHOICES, default='Unknown')
    findings        = models.TextField(blank=True)            # JSON-serialised list
    ioc_indicators  = models.TextField(blank=True)            # JSON-serialised list
    analysis_summary= models.TextField(blank=True)

    # Chain-of-custody timestamps
    uploaded_at     = models.DateTimeField(auto_now_add=True)
    analysed_at     = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.case_id} – {self.original_name} [{self.threat_level}]"

    class Meta:
        db_table = 'EvidenceFiles'
        ordering = ['-uploaded_at']
