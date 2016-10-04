<div class="cmssec_settings_page">
	<div class="settings_form">
		<form action="options.php" method="post">
			<!--
			<input type="text" style="display: none;" name="action" value="update_settings" readonly>
			Plugin Enabled: <input type="checkbox" name="enabled"> <br />
			<input type="submit" value="Save">
			-->
			<?php echo "testing"; ?>
			<?php settings_fields( 'cmssecd_options_options' ); ?>
			<?php do_settings_sections( 'cmssecd_options_options' ); ?>
			<?php submit_button(); ?>
		</form>
	</div>
</div>
