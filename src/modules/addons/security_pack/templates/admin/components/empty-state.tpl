<?php
/** Expected variables: string $message */
$message = $message ?? "Nothing to show.";
?>
<p class="sp-empty"><?php echo security_pack_e($message); ?></p>
